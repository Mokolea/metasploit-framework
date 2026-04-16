# frozen_string_literal: true

require 'securerandom'
require 'socket'

module MsfMcp
  # Manages the lifecycle of a Metasploit RPC server process.
  #
  # Probes the configured RPC port, auto-starts the server via Process.spawn
  # of msfrpcd, and cleans up the child process on shutdown.
  class RpcManager
    LOCALHOST_HOSTS = %w[localhost 127.0.0.1 ::1].freeze
    DEFAULT_WAIT_TIMEOUT = 30
    DEFAULT_WAIT_INTERVAL = 1
    STOP_GRACE_PERIOD = 5

    attr_reader :rpc_pid

    # @param config [Hash] Application configuration hash
    # @param output [IO] Output stream for status messages
    # @param logger [MsfMcp::Logging::Logger, nil] Optional logger
    def initialize(config:, output:, logger: nil)
      @config = config
      @output = output
      @logger = logger
      @rpc_pid = nil
      @rpc_managed = false
    end

    # Whether this manager started and is managing an RPC server process.
    #
    # @return [Boolean]
    def rpc_managed?
      @rpc_managed
    end

    # Probe the configured RPC port to check if a server is listening.
    #
    # @return [Boolean]
    def rpc_available?
      host = @config[:msf_api][:host]
      port = @config[:msf_api][:port]

      socket = TCPSocket.new(host, port)
      socket.close
      log(level: 'DEBUG', message: "RPC server is available at #{host}:#{port}")
      true
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH,
           Errno::ETIMEDOUT, SocketError
      false
    end

    # Whether auto-start is enabled based on config, API type, and host.
    #
    # Auto-start is only supported for:
    # - MessagePack API type (not JSON-RPC)
    # - Localhost connections (cannot start a remote RPC server)
    # - When auto_start_rpc config is not explicitly false
    #
    # @return [Boolean]
    def auto_start_enabled?
      return false if @config[:msf_api][:type] != 'messagepack'
      return false unless localhost?
      return false if @config[:msf_api][:auto_start_rpc] == false

      true
    end

    # Start the Metasploit RPC server by spawning msfrpcd.
    #
    # Credentials are passed via environment variables to avoid exposing
    # them on the command line.
    #
    # @return [void]
    # @raise [MsfMcp::Metasploit::RpcStartupError] If the server cannot be started
    def start_rpc_server
      if @rpc_managed
        @output.puts 'RPC server is already managed by this process'
        return
      end

      @output.puts 'Starting Metasploit RPC server...'
      log(level: 'INFO', message: 'Starting Metasploit RPC server')

      unless File.executable?(MSFRPCD_PATH)
        raise MsfMcp::Metasploit::RpcStartupError,
              'msfrpcd executable not found. Cannot auto-start RPC server.'
      end

      args = build_msfrpcd_args
      env = {
        'MSF_RPC_USER' => @config[:msf_api][:user].to_s,
        'MSF_RPC_PASS' => @config[:msf_api][:password].to_s
      }

      pid = Process.spawn(env, MSFRPCD_PATH, *args, %i[out err] => File::NULL)

      @rpc_pid = pid
      @rpc_managed = true
      @output.puts "RPC server started via msfrpcd (PID: #{pid})"
    end

    # Wait for the RPC server to become available.
    #
    # @param timeout [Integer] Maximum seconds to wait (default: 30)
    # @param interval [Integer] Seconds between probes (default: 1)
    # @return [true] When the server becomes available
    # @raise [MsfMcp::Metasploit::ConnectionError] If timeout is reached
    # @raise [MsfMcp::Metasploit::RpcStartupError] If the managed process exits
    def wait_for_rpc(timeout: DEFAULT_WAIT_TIMEOUT, interval: DEFAULT_WAIT_INTERVAL)
      deadline = Time.now + timeout

      loop do
        if rpc_available?
          @output.puts 'RPC server is ready'
          return true
        end

        check_managed_process_alive! if @rpc_managed

        if Time.now >= deadline
          raise MsfMcp::Metasploit::ConnectionError,
                "Timed out waiting for RPC server after #{timeout} seconds"
        end

        @output.puts 'Waiting for RPC server to become available...'
        sleep(interval)
      end
    end

    # Stop the managed RPC server process.
    #
    # @return [void]
    def stop_rpc_server
      return unless @rpc_managed

      @output.puts 'Stopping managed RPC server...'
      log(level: 'INFO', message: "Stopping managed RPC server (PID: #{@rpc_pid})")

      begin
        Process.kill('TERM', @rpc_pid)
        graceful_wait
      rescue Errno::ESRCH
        # Process already dead — that's fine
      rescue Errno::EPERM
        @output.puts "Warning: no permission to stop RPC process #{@rpc_pid}"
      end

      @rpc_pid = nil
      @rpc_managed = false
    end

    # Ensure an RPC server is available, auto-starting if needed.
    #
    # When no credentials are provided and auto-start is enabled, random
    # credentials are generated and written back into the config hash so the
    # application can use them to authenticate.
    #
    # @return [void]
    # @raise [MsfMcp::Metasploit::RpcStartupError] If the RPC server is already
    #   running but no credentials were provided
    def ensure_rpc_available
      if rpc_available?
        unless credentials_provided?
          raise MsfMcp::Metasploit::RpcStartupError,
                'RPC server is already running but no credentials were provided. ' \
                'Use --user and --password options to authenticate with the existing server.'
        end

        @output.puts 'Metasploit RPC server is already running'
        return
      end

      unless auto_start_enabled?
        if localhost?
          @output.puts 'RPC server is not running and auto-start is disabled'
        else
          @output.puts "Cannot auto-start RPC on remote host #{@config[:msf_api][:host]}. " \
                       'Please start the RPC server manually.'
        end
        return
      end

      generate_random_credentials unless credentials_provided?
      start_rpc_server
      wait_for_rpc
    end

    private

    # Absolute path to msfrpcd relative to the framework root.
    MSFRPCD_PATH = File.expand_path('../../msfrpcd', __dir__).freeze

    # Build command-line arguments for msfrpcd.
    #
    # Note: credentials are passed via environment variables (MSF_RPC_USER,
    # MSF_RPC_PASS) rather than command-line arguments for security.
    #
    # @return [Array<String>]
    def build_msfrpcd_args
      args = ['-f'] # foreground mode
      args.push('-a', @config[:msf_api][:host].to_s)
      args.push('-p', @config[:msf_api][:port].to_s)
      args.push('-S') if @config[:msf_api][:ssl] == false
      args
    end

    # Check whether the host is a localhost address.
    #
    # @return [Boolean]
    def localhost?
      LOCALHOST_HOSTS.include?(@config[:msf_api][:host].to_s.downcase)
    end

    # Whether both user and password are present in the configuration.
    #
    # @return [Boolean]
    def credentials_provided?
      user = @config[:msf_api][:user]
      password = @config[:msf_api][:password]
      !user.to_s.strip.empty? && !password.to_s.strip.empty?
    end

    # Generate random credentials and write them into the config hash.
    #
    # @return [void]
    def generate_random_credentials
      @config[:msf_api][:user] = SecureRandom.hex(8)
      @config[:msf_api][:password] = SecureRandom.hex(16)
      @output.puts 'Generated random credentials for auto-started RPC server'
      log(level: 'INFO', message: 'Generated random credentials for auto-started RPC server')
    end

    # Check if the managed child process is still alive.
    # Raises RpcStartupError if it has exited.
    def check_managed_process_alive!
      return unless @rpc_pid

      result = Process.waitpid(@rpc_pid, Process::WNOHANG)
      return unless result

      @rpc_pid = nil
      @rpc_managed = false
      raise MsfMcp::Metasploit::RpcStartupError,
            'RPC server process exited unexpectedly'
    end

    # Wait for the child process to exit after SIGTERM, escalating to
    # SIGKILL if it does not exit within the grace period.
    def graceful_wait
      result = Process.waitpid(@rpc_pid, Process::WNOHANG)
      return if result

      sleep(STOP_GRACE_PERIOD)
      result = Process.waitpid(@rpc_pid, Process::WNOHANG)
      return if result

      # Process did not exit; escalate to SIGKILL
      Process.kill('KILL', @rpc_pid)
      Process.waitpid(@rpc_pid, 0)
    end

    # Log a message if a logger is available.
    #
    # @param level [String] Log level
    # @param message [String] Log message
    def log(level:, message:)
      @logger&.log(level: level, message: message)
    end
  end
end
