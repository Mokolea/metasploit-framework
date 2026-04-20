# frozen_string_literal: true

module Msf::MCP
  ##
  # MCP Server Wrapper for Metasploit Framework
  #
  # This class initializes and manages the MCP server with all registered tools.
  # It provides a clean interface for starting/stopping the server and integrates
  # with the Metasploit client and security layers.
  #
  # The Server expects fully configured and authenticated dependencies to be
  # provided during initialization. It does not handle configuration loading
  # or client authentication - those are responsibilities of the calling code.
  #
  class Server

    ##
    # Initialize the MCP server with required dependencies
    #
    # @param msf_client [Metasploit::Client] Configured and authenticated Metasploit client
    # @param rate_limiter [Security::RateLimiter] Configured rate limiter
    # @param logger [Logging::Logger] Optional logger for HTTP transport (default: nil)
    #
    def initialize(msf_client:, rate_limiter:, logger: nil)
      @msf_client = msf_client
      @logger = logger

      # Create server context (passed to all tool calls)
      # Tools only need msf_client and rate_limiter
      @server_context = {
        msf_client: @msf_client,
        rate_limiter: rate_limiter
      }

      # Create MCP configuration with instrumentation callbacks
      mcp_config = ::MCP::Configuration.new
      if @logger
        mcp_config.instrumentation_callback = create_instrumentation_callback
        mcp_config.exception_reporter = create_exception_reporter
      end

      # Initialize MCP server with all tools
      @mcp_server = ::MCP::Server.new(
        name: 'msfmcp',
        version: Msf::MCP::Application::VERSION,
        tools: [
          Tools::SearchModules,
          Tools::ModuleInfo,
          Tools::HostInfo,
          Tools::ServiceInfo,
          Tools::VulnerabilityInfo,
          Tools::NoteInfo,
          Tools::CredentialInfo,
          Tools::LootInfo
        ],
        server_context: @server_context,
        configuration: mcp_config
      )
    end

    ##
    # Start the MCP server with specified transport
    #
    # @param transport [Symbol] Transport type (:stdio or :http)
    # @param host [String] Host address for HTTP transport (default: 'localhost')
    # @param port [Integer] Port number for HTTP transport (default: 3000)
    #
    # @return [MCP::Server] The MCP server instance (for testing purposes)
    # @raise [ArgumentError] If an unknown transport is specified
    #
    def start(transport: :stdio, host: 'localhost', port: 3000)
      case transport
      when :stdio
        start_stdio
      when :http
        start_http(host, port)
      else
        raise ArgumentError, "Unknown transport: #{transport}. Use :stdio or :http"
      end
    end

    ##
    # Shutdown the MCP server and cleanup resources
    #
    def shutdown
      @msf_client&.shutdown
      @mcp_server = nil
    end

    private

    ##
    # Start stdio transport (for CLI usage)
    #
    # @return [MCP::Server] The MCP server instance (for testing purposes)
    #
    def start_stdio
      transport = ::MCP::Server::Transports::StdioTransport.new(@mcp_server)
      @mcp_server.transport = transport
      transport.open
      @mcp_server
    end

    ##
    # Start HTTP transport (for web/network usage)
    #
    # @param host [String] Host address to bind to
    # @param port [Integer] Port to listen on
    #
    # @return [MCP::Server] The MCP server instance (for testing purposes)
    #
    def start_http(host, port)
      require 'rack'
      require 'rack/handler/puma'

      transport = ::MCP::Server::Transports::StreamableHTTPTransport.new(@mcp_server)
      @mcp_server.transport = transport

      # Create the Rack application following official MCP example
      app = proc do |env|
        request = Rack::Request.new(env)
        log_http_request(request) if @logger
        response = transport.handle_request(request)
        log_http_response(request, response) if @logger
        response
      end

      # Build the Rack application with middleware
      rack_app = Rack::Builder.new do
        use Rack::ShowExceptions
        run app
      end

      # Start Puma server using the handler appropriate for the Rack version.
      # Rackup::Handler is available with rackup >= 2.x / Rack 3+;
      # Rack::Handler is used with Rack < 3 and rackup 1.x.
      puma_handler = if defined?(Rackup::Handler)
                       Rackup::Handler::Puma
                     else
                       Rack::Handler::Puma
                     end
      puma_handler.run(
        rack_app,
        Port: port,
        Host: host,
        Silent: !@logger
      )

      @mcp_server
    end

    ##
    # Log HTTP request details
    #
    # @param request [Rack::Request] The HTTP request
    #
    def log_http_request(request)
      return unless @logger

      if request.post?
        body = request.body.read
        request.body.rewind
        begin
          parsed_body = JSON.parse(body)
          @logger.log(
            level: 'INFO',
            message: "HTTP Request: #{parsed_body['method']} (id: #{parsed_body['id']})",
            context: {
              method: parsed_body['method'],
              id: parsed_body['id'],
              params: parsed_body['params']
            }
          )
        rescue JSON::ParserError
          @logger.log(level: 'WARN', message: 'Invalid JSON in HTTP request')
        end
      elsif request.get?
        session_id = request.env['HTTP_MCP_SESSION_ID'] ||
                     Rack::Utils.parse_query(request.env['QUERY_STRING'])['sessionId']
        @logger.log(
          level: 'INFO',
          message: 'SSE connection request',
          context: { session_id: session_id }
        )
      end
    end

    ##
    # Log HTTP response details
    #
    # @param request [Rack::Request] The HTTP request
    # @param response [Array] The Rack response [status, headers, body]
    #
    def log_http_response(request, response)
      return unless @logger

      status, headers, body = response

      if body.is_a?(Array) && !body.empty? && request.post?
        begin
          parsed_response = JSON.parse(body.first)
          if parsed_response['error']
            @logger.log(
              level: 'ERROR',
              message: "HTTP Response error: #{parsed_response['error']['message']}",
              context: { error_code: parsed_response['error']['code'] }
            )
          elsif parsed_response['accepted']
            @logger.log(level: 'INFO', message: 'Response sent via SSE stream')
          else
            @logger.log(
              level: 'INFO',
              message: "HTTP Response: success (id: #{parsed_response['id']})",
              context: {
                id: parsed_response['id'],
                session_id: headers['Mcp-Session-Id']
              }
            )
          end
        rescue JSON::ParserError
          @logger.log(level: 'WARN', message: 'Invalid JSON in HTTP response')
        end
      elsif request.get? && status == 200
        @logger.log(level: 'INFO', message: 'SSE stream established')
      end
    end

    private

    ##
    # Create instrumentation callback for MCP SDK
    #
    # This callback receives information about:
    # - Tool calls (with tool_name, duration)
    # - Prompt calls (with prompt_name, duration)
    # - Resource calls (with resource_uri, duration)
    # - Errors (with error type, e.g., tool_not_found)
    # - Any additional data from the MCP SDK
    #
    # All data keys are logged in the context.
    #
    # @return [Proc] Callback that logs instrumentation data
    #
    def create_instrumentation_callback
      return nil unless @logger

      ->(data) do
        # Determine log level based on presence of error
        level = data[:error] ? 'ERROR' : 'INFO'

        # Build message based on instrumentation type
        # Use first available key to create a descriptive message
        message = if data[:error]
                    "MCP Error: #{data[:error]}"
                  elsif data[:tool_name]
                    "Tool call: #{data[:tool_name]}"
                  elsif data[:prompt_name]
                    "Prompt call: #{data[:prompt_name]}"
                  elsif data[:resource_uri]
                    "Resource call: #{data[:resource_uri]}"
                  elsif data[:method]
                    "Method call: #{data[:method]}"
                  else
                    "MCP instrumentation"
                  end

        # Add duration to message if available
        message << " (#{(data[:duration] * 1000).round(2)}ms)" if data[:duration]

        # Log with all data keys preserved in context
        @logger.log(
          level: level,
          message: message,
          context: data  # All keys from data hash are logged here
        )
      end
    end

    ##
    # Create exception reporter callback for MCP SDK
    #
    # This callback is invoked for any exception during request processing.
    # It receives:
    # - exception: The Ruby exception object
    # - context: Hash with :request (JSON string) or :notification (method name string)
    #
    # @return [Proc] Callback that logs exceptions
    #
    def create_exception_reporter
      return nil unless @logger

      ->(exception, context) do
        # Determine the context type and parse data
        error_context = {}

        if context[:request]
          error_context[:type] = 'request'
          if context[:request].is_a?(Hash)
            error_context[:method] = context.dig(:request, :name) || 'unknown'
            error_context[:arguments] = context.dig(:request, :arguments) || []
          else
            error_context[:raw_data] = context[:request].inspect
          end
        elsif context[:notification]
          error_context[:type] = 'notification'
          # context[:notification] is the notification method name (string)
          error_context[:method] = context[:notification]
        else
          error_context[:type] = 'unknown'
          error_context[:raw_data] = context.inspect
        end

        @logger.log_error(
          exception: exception,
          message: "Error during #{error_context[:type]} processing#{error_context[:method] ? " (#{error_context[:method]})" : ''}",
          context: error_context
        )
      end
    end
  end
end
