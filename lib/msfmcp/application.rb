# frozen_string_literal: true

require 'msfmcp'
require 'optparse'
require_relative 'logging/logger'

module MsfMcp
  # Main application class that orchestrates the MCP server startup and lifecycle
  class Application
    VERSION = '0.1.0'
    BANNER = <<~BANNER
      MSF MCP Server v#{VERSION}
      Model Context Protocol server for Metasploit Framework
    BANNER

    # For testing purposes:
    attr_reader :config, :logger, :msf_client, :mcp_server, :rate_limiter, :options, :rpc_manager

    # Initialize the application with command-line arguments
    #
    # @param argv [Array<String>] Command-line arguments
    # @param output [IO] Output stream for messages (default: $stderr)
    def initialize(argv = ARGV, output: $stderr)
      @argv = argv.dup
      @output = output
      @options = {}
      @logger = nil
      @config = nil
      @msf_client = nil
      @mcp_server = nil
      @rate_limiter = nil
      @rpc_manager = nil
    end

    # Run the application
    #
    # @return [void]
    def run
      parse_arguments
      install_signal_handlers
      load_configuration
      validate_configuration
      initialize_logger
      initialize_rate_limiter
      ensure_rpc_server
      initialize_metasploit_client
      authenticate_metasploit
      initialize_mcp_server
      start_mcp_server
    rescue MsfMcp::Config::ValidationError, MsfMcp::Config::ConfigurationError => e
      handle_configuration_error(e)
    rescue Errno::ENOENT => e
      handle_file_not_found_error(e)
    rescue MsfMcp::Metasploit::ConnectionError => e
      handle_connection_error(e)
    rescue MsfMcp::Metasploit::APIError => e
      handle_api_error(e)
    rescue MsfMcp::Metasploit::AuthenticationError => e
      handle_authentication_error(e)
    rescue MsfMcp::Metasploit::RpcStartupError => e
      handle_rpc_startup_error(e)
    rescue StandardError => e
      handle_fatal_error(e)
    end

    # Shutdown the application gracefully
    #
    # Performs cleanup operations before process termination:
    # - Logs shutdown event
    # - Closes MCP server and Metasploit client connections
    # - Cleans up resources
    #
    # @param signal [String] Signal name (e.g., 'INT', 'TERM')
    # @return [void]
    def shutdown(signal = 'INT')
      @logger.log(
        level: 'INFO',
        message: 'Shutting down',
        context: { signal: "SIG#{signal}" }
      ) if @logger

      # Gracefully shutdown MCP server and Metasploit client
      @mcp_server&.shutdown if @mcp_server
      @rpc_manager&.stop_rpc_server

      @output.puts "\nShutdown complete"
    end

    private

    # Parse command-line arguments
    #
    # @return [void]
    def parse_arguments
      parser = OptionParser.new do |opts|
        opts.banner = BANNER + "\nUsage: msfmcp [options]"

        opts.on('--config PATH', 'Path to configuration file') do |path|
          @options[:config_path] = File.expand_path(path)
        end

        opts.on('--enable-logging', 'Enable file logging with sanitization') do
          @options[:enable_logging_cli] = true
        end

        opts.on('--log-file PATH', 'Log file path (overrides config file)') do |path|
          @options[:log_file_cli] = path
        end

        opts.on('--user USER', 'MSF API username (for MessagePack auth)') do |user|
          @options[:msf_user_cli] = user
        end

        opts.on('--password PASS', 'MSF API password (for MessagePack auth)') do |password|
          @options[:msf_password_cli] = password
        end

        opts.on('--no-auto-start-rpc', 'Disable automatic RPC server startup') do
          @options[:no_auto_start_rpc] = true
        end

        opts.on('-h', '--help', 'Show this help message') do
          @output.puts opts
          exit 0
        end

        opts.on('-v', '--version', 'Show version information') do
          @output.puts "msfmcp version #{VERSION}"
          exit 0
        end
      end

      parser.parse!(@argv)
    end

    # Initialize the logger with config file settings and CLI overrides
    #
    # Priority: CLI flags > config file > defaults
    #
    # @return [void]
    def initialize_logger
      # Use CLI flags if provided, otherwise use config file values
      if @options[:enable_logging_cli] || @config.dig(:logging, :enabled)
        log_file = @options[:log_file_cli] || @config.dig(:logging, :log_file) || 'msfmcp.log'
        log_level = @config.dig(:logging, :level) || 'INFO'

        @logger = MsfMcp::Logging::Logger.new(
          log_file: log_file,
          log_level: log_level
        )
      end
    end

    # Install signal handlers for graceful shutdown
    #
    # @return [void]
    def install_signal_handlers
      Signal.trap('INT') { shutdown('INT'); exit 0 }
      Signal.trap('TERM') { shutdown('TERM'); exit 0 }
    end

    # Load configuration from file or use defaults
    #
    # @return [void]
    def load_configuration
      if @options[:config_path]
        @output.puts "Loading configuration from #{@options[:config_path]}"
        @config = MsfMcp::Config::Loader.load(@options[:config_path])
      else
        @output.puts "No configuration file specified, using defaults"
        @config = MsfMcp::Config::Loader.load_from_hash({})
      end

      # Apply CLI authentication overrides (highest priority)
      if @options[:msf_user_cli]
        @config[:msf_api][:user] = @options[:msf_user_cli]
      end
      if @options[:msf_password_cli]
        @config[:msf_api][:password] = @options[:msf_password_cli]
      end
      if @options[:no_auto_start_rpc]
        @config[:msf_api][:auto_start_rpc] = false
      end
    end

    # Validate the loaded configuration
    #
    # @return [void]
    def validate_configuration
      @output.puts "Validating configuration..."
      MsfMcp::Config::Validator.validate!(@config)
      @output.puts "Configuration valid"
    end

    # Initialize the rate limiter
    #
    # @return [void]
    def initialize_rate_limiter
      @rate_limiter = MsfMcp::Security::RateLimiter.new(
        requests_per_minute: @config.dig(:rate_limit, :requests_per_minute) || 60,
        burst_size: @config.dig(:rate_limit, :burst_size)
      )
    end

    # Ensure the Metasploit RPC server is available, auto-starting if needed
    #
    # @return [void]
    def ensure_rpc_server
      @rpc_manager = MsfMcp::RpcManager.new(
        config: @config,
        output: @output,
        logger: @logger
      )
      @rpc_manager.ensure_rpc_available
    end

    # Initialize the Metasploit client
    #
    # @return [void]
    def initialize_metasploit_client
      @output.puts "Connecting to Metasploit RPC at #{@config[:msf_api][:host]}:#{@config[:msf_api][:port]}"
      @msf_client = MsfMcp::Metasploit::Client.new(
        api_type: @config[:msf_api][:type],
        host: @config[:msf_api][:host],
        port: @config[:msf_api][:port],
        endpoint: @config[:msf_api][:endpoint],
        token: @config[:msf_api][:token],
        ssl: @config[:msf_api][:ssl],
        logger: @logger
      )
    end

    # Authenticate with Metasploit if using MessagePack
    #
    # @return [void]
    def authenticate_metasploit
      if @config[:msf_api][:type] == 'messagepack'
        @output.puts "Authenticating with Metasploit..."
        @msf_client.authenticate(@config[:msf_api][:user].to_s, @config[:msf_api][:password].to_s)
        @output.puts "Authentication successful"
      else
        @output.puts "Using JSON-RPC with token authentication"
      end
    end

    # Initialize the MCP server
    #
    # @return [void]
    def initialize_mcp_server
      @output.puts "Initializing MCP server..."
      @mcp_server = MsfMcp::MCP::Server.new(
        msf_client: @msf_client,
        rate_limiter: @rate_limiter,
        logger: @logger
      )
    end

    # Start the MCP server with configured transport
    #
    # @return [void]
    def start_mcp_server
      transport = (@config.dig(:mcp, :transport) || 'stdio').to_sym
      host = @config.dig(:mcp, :host) || 'localhost'
      port = @config.dig(:mcp, :port) || 3000

      if transport == :http
        @output.puts "Starting MCP server on HTTP transport..."
        @output.puts "Server listening on http://#{host}:#{port}"
        @output.puts "Press Ctrl+C to shutdown"
        @mcp_server.start(transport: :http, host: host, port: port)
      else
        @output.puts "Starting MCP server on stdio transport..."
        @output.puts "Server ready - waiting for MCP requests"
        @output.puts "Press Ctrl+C to shutdown"
        @mcp_server.start(transport: :stdio)
      end
    end

    # Error handlers

    def handle_configuration_error(error)
      @logger.log_error(
        exception: error,
        message: 'Configuration validation failed',
        context: {}
      ) if @logger
      @output.puts "Configuration validation failed: #{error.message}"
      exit 1
    end

    def handle_file_not_found_error(error)
      @logger.log_error(
        exception: error,
        message: 'Configuration file not found',
        context: {}
      ) if @logger
      @output.puts "Configuration file not found: #{@options[:config_path]}"
      @output.puts "Create a configuration file or specify a valid path with --config"
      exit 1
    end

    def handle_connection_error(error)
      @logger.log_error(
        exception: error,
        message: 'Connection error',
        context: { host: @config[:msf_api][:host], port: @config[:msf_api][:port] }
      ) if @logger
      @output.puts "Connection error to Metasploit RPC at #{@config[:msf_api][:host]}:#{@config[:msf_api][:port]} - #{error.message}"
      exit 1
    end

    def handle_api_error(error)
      @logger.log_error(
        exception: error,
        message: 'Metasploit API error',
        context: {}
      ) if @logger
      @output.puts "Metasploit API error: #{error.message}"
      exit 1
    end

    def handle_authentication_error(error)
      @logger.log_error(
        exception: error,
        message: 'Authentication error',
        context: { username: @config[:msf_api][:user].to_s }
      ) if @logger
      @output.puts "Authentication error (username: #{@config[:msf_api][:user]}): #{error.message}"
      exit 1
    end

    def handle_rpc_startup_error(error)
      @logger.log_error(
        exception: error,
        message: 'RPC startup error',
        context: {}
      ) if @logger
      @output.puts "RPC startup error: #{error.message}"
      exit 1
    end

    def handle_fatal_error(error)
      @logger.log_error(
        exception: error,
        message: 'Fatal error during startup',
        context: {}
      ) if @logger
      @output.puts "Fatal error: #{error.message}"
      @output.puts error.backtrace.first(5).join("\n") if error.backtrace
      exit 1
    end
  end
end
