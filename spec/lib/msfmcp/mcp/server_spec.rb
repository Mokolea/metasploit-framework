# frozen_string_literal: true

require 'msfmcp'

RSpec.describe MsfMcp::MCP::Server do
  let(:valid_config) do
    {
      msf_api: {
        type: 'messagepack',
        host: 'localhost',
        port: 55553,
        endpoint: '/api/',
        user: 'test_user',
        password: 'test_password'
      },
      rate_limit: {
        requests_per_minute: 60,
        burst_size: 10
      }
    }
  end

  let(:mock_msf_client) do
    instance_double(MsfMcp::Metasploit::Client).tap do |client|
      allow(client).to receive(:shutdown)
    end
  end

  let(:rate_limiter) do
    MsfMcp::Security::RateLimiter.new(
      requests_per_minute: valid_config.dig(:rate_limit, :requests_per_minute) || 60,
      burst_size: valid_config.dig(:rate_limit, :burst_size)
    )
  end

  let(:mock_mcp_server) do
    instance_double(::MCP::Server).tap do |server|
      allow(server).to receive(:transport=)
    end
  end

  let(:mock_transport) do
    instance_double(::MCP::Server::Transports::StdioTransport).tap do |transport|
      allow(transport).to receive(:open)
    end
  end

  describe '#initialize' do
    it 'initializes with required dependencies' do
      # Mock the transport to prevent the server to actually start listening
      transport = instance_double(MCP::Server::Transports::StdioTransport)
      allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(transport)
      allow(transport).to receive(:open)

      server = described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
      mcp_server = server.start

      expect(mcp_server.server_context[:msf_client]).to eq(mock_msf_client)
      expect(mcp_server.server_context[:rate_limiter]).to eq(rate_limiter)
    end

    it 'creates MCP server with correct parameters' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          name: 'msfmcp',
          version: MsfMcp::Application::VERSION,
          tools: be_an(Array),
          server_context: be_a(Hash)
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'registers all MCP tools' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          tools: array_including(
            MsfMcp::MCPTools::SearchModules,
            MsfMcp::MCPTools::ModuleInfo,
            MsfMcp::MCPTools::HostInfo,
            MsfMcp::MCPTools::ServiceInfo,
            MsfMcp::MCPTools::VulnerabilityInfo,
            MsfMcp::MCPTools::NoteInfo,
            MsfMcp::MCPTools::CredentialInfo,
            MsfMcp::MCPTools::LootInfo
          )
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'creates server context with msf_client and rate_limiter' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          server_context: hash_including(
            msf_client: mock_msf_client,
            rate_limiter: rate_limiter
          )
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'does not include config hash in server_context' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          server_context: hash_not_including(:config)
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end
  end

  describe '#start' do
    let(:server) do
      allow(::MCP::Server).to receive(:new).and_return(mock_mcp_server)
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    context 'with stdio transport' do
      it 'creates stdio transport' do
        expect(::MCP::Server::Transports::StdioTransport).to receive(:new).with(mock_mcp_server).and_return(mock_transport)

        server.start(transport: :stdio)
      end

      it 'sets transport on mcp_server' do
        allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(mock_transport)

        expect(mock_mcp_server).to receive(:transport=).with(mock_transport)

        server.start(transport: :stdio)
      end

      it 'opens the transport' do
        allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(mock_transport)

        expect(mock_transport).to receive(:open)

        server.start(transport: :stdio)
      end

      it 'defaults to stdio when no transport specified' do
        expect(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(mock_transport)

        server.start
      end
    end

    context 'with http transport' do
      let(:mock_http_transport) do
        instance_double(::MCP::Server::Transports::StreamableHTTPTransport)
      end
      let(:puma_handler) { double('puma_handler') }
      let(:rack_app) { double('rack_app') }

      before do
        # Stub #require to prevent actually loading rack and rack/handler/puma
        allow(server).to receive(:require).with('rack').and_return(true)
        allow(server).to receive(:require).with('rack/handler/puma').and_return(true)

        stub_const('Rack::Handler::Puma', puma_handler)
        stub_const('Rack::Builder', double('Rack::Builder'))

        allow(::MCP::Server::Transports::StreamableHTTPTransport).to receive(:new).and_return(mock_http_transport)
        allow(Rack::Builder).to receive(:new).and_return(rack_app)

        allow(puma_handler).to receive(:run)
      end

      it 'creates http transport' do
        expect(::MCP::Server::Transports::StreamableHTTPTransport).to receive(:new).with(mock_mcp_server)

        server.start(transport: :http, port: 3000)
      end

      it 'sets transport on mcp_server' do
        expect(mock_mcp_server).to receive(:transport=).with(mock_http_transport)

        server.start(transport: :http, port: 3000)
      end

      it 'starts Puma server via Rack handler' do
        expect(puma_handler).to receive(:run).with(
          anything,  # Rack app
          hash_including(
            Port: 3000,
            Host: 'localhost'
          )
        )

        server.start(transport: :http, port: 3000)
      end

      it 'allows custom port' do
        expect(puma_handler).to receive(:run).with(
          anything,
          hash_including(Port: 8080)
        )

        server.start(transport: :http, port: 8080)
      end

      it 'creates a Rack application' do
        expect(puma_handler).to receive(:run) do |rack_app, options|
          expect(rack_app).to be(rack_app)
          expect(options).to include(Port: 3000, Host: 'localhost')
        end

        server.start(transport: :http, port: 3000)
      end
    end

    context 'with invalid transport' do
      it 'raises ArgumentError' do
        expect {
          server.start(transport: :websocket)
        }.to raise_error(ArgumentError, /Unknown transport.*websocket/)
      end

      it 'error message mentions valid transports' do
        expect {
          server.start(transport: :invalid)
        }.to raise_error(ArgumentError, /stdio.*http/)
      end
    end
  end

  describe '#shutdown' do
    let(:server) do
      allow(::MCP::Server).to receive(:new).and_return(mock_mcp_server)
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'shuts down the Metasploit client' do
      expect(mock_msf_client).to receive(:shutdown)

      server.shutdown
    end

    it 'handles nil msf_client gracefully' do
      server.instance_variable_set(:@msf_client, nil)

      expect { server.shutdown }.not_to raise_error
    end

    it 'clears mcp_server reference' do
      server.shutdown

      expect(server.instance_variable_get(:@mcp_server)).to be_nil
    end

    it 'can be called multiple times safely' do
      expect {
        server.shutdown
        server.shutdown
      }.not_to raise_error
    end
  end

  describe 'dependency injection' do
    let(:server) do
      # Create server with pre-authenticated client
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end
    let(:mcp_server) { server.start }

    before do
      # Mock the transport to prevent the server to actually start listening
      transport = instance_double(MCP::Server::Transports::StdioTransport)
      allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(transport)
      allow(transport).to receive(:open)
    end

    it 'uses the provided authenticated client' do
      # The provided client should be used
      expect(mcp_server.server_context[:msf_client]).to eq(mock_msf_client)
      expect(mcp_server.server_context[:msf_client].object_id).to eq(mock_msf_client.object_id)
    end

    it 'passes the provided client to server_context' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          server_context: hash_including(
            msf_client: mock_msf_client
          )
        )
      ).and_return(mock_mcp_server)

      server
    end

    context 'with a custom rate limiter' do
      let(:rate_limiter) do
        MsfMcp::Security::RateLimiter.new(
          requests_per_minute: 120,
          burst_size: 20
        )
      end

      it 'uses the provided rate_limiter' do
        expect(mcp_server.server_context[:rate_limiter]).to eq(rate_limiter)
        expect(mcp_server.server_context[:rate_limiter].instance_variable_get(:@requests_per_minute)).to eq(120)
        expect(mcp_server.server_context[:rate_limiter].instance_variable_get(:@burst_size)).to eq(20)
      end
    end
  end

  # Instrumentation and logging tests
  describe 'instrumentation and logging' do
    require 'tempfile'

    let(:log_file) { Tempfile.new(['test_log', '.log']) }
    let(:logger) { MsfMcp::Logging::Logger.new(log_file: log_file.path) }
    let(:server_with_logger) do
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter,
        logger: logger
      )
    end
    let(:mcp_server_with_logger) { server_with_logger.start }

    before do
      # Mock the transport to prevent the server to actually start listening
      transport = instance_double(MCP::Server::Transports::StdioTransport)
      allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(transport)
      allow(transport).to receive(:open)
    end

    after do
      log_file.close
      log_file.unlink
    end

    describe 'instrumentation_callback' do
      it 'is configured when logger is provided' do
        expect(mcp_server_with_logger.configuration.instrumentation_callback).not_to be_nil
        expect(mcp_server_with_logger.configuration.instrumentation_callback).to be_a(Proc)
      end

      context 'when logger is not provided' do
        let(:server_without_logger) do
          described_class.new(
            msf_client: mock_msf_client,
            rate_limiter: rate_limiter,
            logger: nil
          )
        end
        let(:mcp_server_without_logger) { server_without_logger.start }

        it 'uses a default no-op callback' do
          expect(mcp_server_without_logger.configuration.instrumentation_callback).not_to be_nil
          expect(mcp_server_without_logger.configuration.instrumentation_callback).to be_a(Proc)
          expect(mcp_server_without_logger.configuration.instrumentation_callback.call(nil)).to be_nil
        end
      end

      it 'logs instrumentation data with errors' do
        data = {
          method: 'tools/call',
          tool_name: 'test_tool',
          error: 'tool_not_found',
          duration: 0.123
        }

        mcp_server_with_logger.configuration.instrumentation_callback.call(data)

        log_content = File.read(log_file.path)
        expect(log_content).to include('ERROR')
        expect(log_content).to include('MCP Error: tool_not_found')
        expect(log_content).to include('test_tool')
      end

      it 'logs successful tool calls' do
        data = {
          method: 'tools/call',
          tool_name: 'search_modules',
          duration: 0.456
        }

        mcp_server_with_logger.configuration.instrumentation_callback.call(data)

        log_content = File.read(log_file.path)
        expect(log_content).to include('INFO')
        expect(log_content).to include('Tool call: search_modules')
        expect(log_content).to include('456')  # Duration in ms
      end

      it 'logs missing_required_arguments errors' do
        data = {
          method: 'tools/call',
          tool_name: 'msf_module_info',
          error: 'missing_required_arguments',
          duration: 0.005
        }

        mcp_server_with_logger.configuration.instrumentation_callback.call(data)

        log_content = File.read(log_file.path)
        expect(log_content).to include('ERROR')
        expect(log_content).to include('MCP Error: missing_required_arguments')
        expect(log_content).to include('msf_module_info')
        expect(log_content).to include('5.0ms')
      end

      it 'logs invalid_schema errors' do
        data = {
          method: 'tools/call',
          tool_name: 'msf_search_modules',
          error: 'invalid_schema',
          duration: 0.002
        }

        mcp_server_with_logger.configuration.instrumentation_callback.call(data)

        log_content = File.read(log_file.path)
        expect(log_content).to include('ERROR')
        expect(log_content).to include('MCP Error: invalid_schema')
        expect(log_content).to include('2.0ms')
      end

      it 'logs prompt calls' do
        data = {
          method: 'prompts/get',
          prompt_name: 'exploit_suggestion',
          duration: 0.123
        }

        mcp_server_with_logger.configuration.instrumentation_callback.call(data)

        log_content = File.read(log_file.path)
        expect(log_content).to include('INFO')
        expect(log_content).to include('Prompt call: exploit_suggestion')
        expect(log_content).to include('123.0ms')
      end

      it 'logs resource calls' do
        data = {
          method: 'resources/read',
          resource_uri: 'msf://exploits/windows',
          duration: 0.089
        }

        mcp_server_with_logger.configuration.instrumentation_callback.call(data)

        log_content = File.read(log_file.path)
        expect(log_content).to include('INFO')
        expect(log_content).to include('Resource call: msf://exploits/windows')
        expect(log_content).to include('89.0ms')
      end

      it 'logs generic method calls without specific type' do
        data = {
          method: 'ping',
          duration: 0.001
        }

        mcp_server_with_logger.configuration.instrumentation_callback.call(data)

        log_content = File.read(log_file.path)
        expect(log_content).to include('INFO')
        expect(log_content).to include('Method call: ping')
        expect(log_content).to include('1.0ms')
      end

      it 'formats duration in milliseconds' do
        data = {
          method: 'tools/call',
          tool_name: 'test_tool',
          duration: 1.23456
        }

        mcp_server_with_logger.configuration.instrumentation_callback.call(data)

        log_content = File.read(log_file.path)
        expect(log_content).to include('1234.56ms')
      end

      it 'logs all data keys in context' do
        data = {
          method: 'tools/call',
          tool_name: 'msf_search_modules',
          duration: 0.234,
          custom_key: 'custom_value',
          another_key: 42,
          nested_data: { foo: 'bar' }
        }

        mcp_server_with_logger.configuration.instrumentation_callback.call(data)

        log_content = File.read(log_file.path)
        parsed_log = JSON.parse(log_content.lines.first)

        expect(parsed_log['context']['method']).to eq('tools/call')
        expect(parsed_log['context']['tool_name']).to eq('msf_search_modules')
        expect(parsed_log['context']['duration']).to eq(0.234)
        expect(parsed_log['context']['custom_key']).to eq('custom_value')
        expect(parsed_log['context']['another_key']).to eq(42)
        expect(parsed_log['context']['nested_data']).to eq({ 'foo' => 'bar' })
      end

      it 'logs fallback message when no specific type key is present' do
        data = { some_unknown_key: 'value' }

        mcp_server_with_logger.configuration.instrumentation_callback.call(data)

        log_content = File.read(log_file.path)
        parsed_log = JSON.parse(log_content.lines.first)
        expect(parsed_log['level']).to eq('INFO')
        expect(parsed_log['message']).to eq('MCP instrumentation')
      end

      it 'omits duration from message when not present' do
        data = { tool_name: 'msf_host_info' }

        mcp_server_with_logger.configuration.instrumentation_callback.call(data)

        log_content = File.read(log_file.path)
        parsed_log = JSON.parse(log_content.lines.first)
        expect(parsed_log['message']).to eq('Tool call: msf_host_info')
        expect(parsed_log['message']).not_to match(/\d+(\.\d+)?ms/)
      end
    end

    describe 'exception_reporter' do
      it 'is configured when logger is provided' do
        expect(mcp_server_with_logger.configuration.exception_reporter).not_to be_nil
        expect(mcp_server_with_logger.configuration.exception_reporter).to be_a(Proc)
      end

      context 'when logger is not provided' do
        let(:server_without_logger) do
          described_class.new(
            msf_client: mock_msf_client,
            rate_limiter: rate_limiter,
            logger: nil
          )
        end
        let(:mcp_server_without_logger) { server_without_logger.start }

        it 'uses a default no-op reporter' do
          expect(mcp_server_without_logger.configuration.exception_reporter).not_to be_nil
          expect(mcp_server_without_logger.configuration.exception_reporter).to be_a(Proc)
          expect(mcp_server_without_logger.configuration.exception_reporter.call(nil, nil)).to be_nil
        end
      end

      it 'logs exceptions with context' do
        exception = StandardError.new('Something went wrong')
        request = {
          name: 'msf_search_modules',
          arguments: { 'name' => 'test_tool' }
        }
        context = { request: request }

        mcp_server_with_logger.configuration.exception_reporter.call(exception, context)

        log_content = File.read(log_file.path)
        expect(log_content).to include('ERROR')
        expect(log_content).to include('Error during request processing')
        expect(log_content).to include('msf_search_modules')
        expect(log_content).to include('Something went wrong')
        expect(log_content).to include('test_tool')
      end

      it 'logs exceptions with notification context' do
        exception = RuntimeError.new('Notification failed')
        context = { notification: 'notifications/initialized' }

        mcp_server_with_logger.configuration.exception_reporter.call(exception, context)

        log_content = File.read(log_file.path)
        expect(log_content).to include('ERROR')
        expect(log_content).to include('Error during notification processing')
        expect(log_content).to include('notifications/initialized')
        expect(log_content).to include('Notification failed')
      end

      it 'logs exceptions with full request details including tool name and arguments' do
        exception = StandardError.new('Database connection timeout')
        request = {
          name: 'msf_search_modules',
          arguments: { 'workspace' => 'default', 'query' => 'windows'}
        }
        context = { request: request }

        mcp_server_with_logger.configuration.exception_reporter.call(exception, context)

        log_content = File.read(log_file.path)
        expect(log_content).to include('ERROR')
        expect(log_content).to include('Error during request processing')
        expect(log_content).to include('Database connection timeout')

        parsed_log = JSON.parse(log_content.lines.first)
        expect(parsed_log['context']['type']).to eq('request')
        expect(parsed_log['context']['method']).to eq('msf_search_modules')
        expect(parsed_log['context']['arguments']).to eq(request[:arguments])
      end

      it 'logs exception class and message' do
        exception = ArgumentError.new('Invalid argument provided')
        request = {
          name: 'msf_search_modules',
          arguments: { 'workspace' => 'default', 'query' => 'windows'}
        }
        context = { request: request }

        mcp_server_with_logger.configuration.exception_reporter.call(exception, context)

        log_content = File.read(log_file.path)
        parsed_log = JSON.parse(log_content.lines.first)

        expect(parsed_log['exception']['class']).to eq('ArgumentError')
        expect(parsed_log['exception']['message']).to eq('Invalid argument provided')
        expect(parsed_log['exception']['backtrace']).to be_an(Array)
      end

      it 'logs exception with notification without method' do
        exception = RuntimeError.new('Generic notification error')
        context = { notification: '' }

        mcp_server_with_logger.configuration.exception_reporter.call(exception, context)

        log_content = File.read(log_file.path)
        expect(log_content).to include('ERROR')
        expect(log_content).to include('Error during notification processing')
        expect(log_content).to include('Generic notification error')
      end

      it 'handles exceptions with empty context' do
        exception = StandardError.new('Unknown error')
        context = {}

        mcp_server_with_logger.configuration.exception_reporter.call(exception, context)

        log_content = File.read(log_file.path)
        expect(log_content).to include('ERROR')
        expect(log_content).to include('Error during unknown processing')
        expect(log_content).to include('Unknown error')
      end

      it 'handles invalid JSON in request string' do
        exception = StandardError.new('Parse error')
        context = { request: 'not valid Hash' }

        mcp_server_with_logger.configuration.exception_reporter.call(exception, context)

        log_content = File.read(log_file.path)
        expect(log_content).to include('ERROR')
        expect(log_content).to include('Error during request processing')
        expect(log_content).to include('Parse error')

        parsed_log = JSON.parse(log_content.lines.first)
        expect(parsed_log['context']['raw_data']).to eq('"not valid Hash"')
      end
    end
  end

  describe 'HTTP request/response logging' do
    require 'tempfile'
    require 'json'
    require 'rack'

    let(:log_file) { Tempfile.new(['test_log', '.log']) }
    let(:logger) { MsfMcp::Logging::Logger.new(log_file: log_file.path) }
    let(:server_with_logger) do
      allow(::MCP::Server).to receive(:new).and_return(mock_mcp_server)
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter,
        logger: logger
      )
    end
    let(:server_without_logger) do
      allow(::MCP::Server).to receive(:new).and_return(mock_mcp_server)
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter,
        logger: nil
      )
    end

    after do
      log_file.close
      log_file.unlink
    end

    describe '#log_http_request' do
      context 'with POST request and valid JSON body' do
        it 'logs method, id, and params' do
          body = StringIO.new({ 'method' => 'tools/call', 'id' => 42, 'params' => { 'name' => 'test' } }.to_json)
          request = instance_double(Rack::Request, post?: true, get?: false, body: body)

          server_with_logger.send(:log_http_request, request)

          log_content = File.read(log_file.path)
          parsed_log = JSON.parse(log_content.lines.first)
          expect(parsed_log['level']).to eq('INFO')
          expect(parsed_log['message']).to eq('HTTP Request: tools/call (id: 42)')
          expect(parsed_log['context']['method']).to eq('tools/call')
          expect(parsed_log['context']['id']).to eq(42)
          expect(parsed_log['context']['params']).to eq({ 'name' => 'test' })
        end
      end

      context 'with POST request and invalid JSON body' do
        it 'logs a warning' do
          body = StringIO.new('not valid json{{{')
          request = instance_double(Rack::Request, post?: true, get?: false, body: body)

          server_with_logger.send(:log_http_request, request)

          log_content = File.read(log_file.path)
          parsed_log = JSON.parse(log_content.lines.first)
          expect(parsed_log['level']).to eq('WARN')
          expect(parsed_log['message']).to eq('Invalid JSON in HTTP request')
        end
      end

      context 'with GET request' do
        it 'logs SSE connection with session_id from header' do
          request = instance_double(Rack::Request,
            post?: false,
            get?: true,
            env: { 'HTTP_MCP_SESSION_ID' => 'abc-123', 'QUERY_STRING' => '' }
          )

          server_with_logger.send(:log_http_request, request)

          log_content = File.read(log_file.path)
          parsed_log = JSON.parse(log_content.lines.first)
          expect(parsed_log['level']).to eq('INFO')
          expect(parsed_log['message']).to eq('SSE connection request')
          expect(parsed_log['context']['session_id']).to eq('abc-123')
        end

        it 'logs SSE connection with session_id from query string' do
          request = instance_double(Rack::Request,
            post?: false,
            get?: true,
            env: { 'QUERY_STRING' => 'sessionId=xyz-789' }
          )

          server_with_logger.send(:log_http_request, request)

          log_content = File.read(log_file.path)
          parsed_log = JSON.parse(log_content.lines.first)
          expect(parsed_log['context']['session_id']).to eq('xyz-789')
        end
      end

      context 'with no logger' do
        it 'returns nil immediately' do
          request = instance_double(Rack::Request)
          expect(server_without_logger.send(:log_http_request, request)).to be_nil
        end
      end

      context 'with non-POST/GET request' do
        it 'does not log anything' do
          request = instance_double(Rack::Request, post?: false, get?: false)

          server_with_logger.send(:log_http_request, request)

          expect(File.read(log_file.path)).to be_empty
        end
      end
    end

    describe '#log_http_response' do
      context 'with POST response containing error' do
        it 'logs the error message and code' do
          request = instance_double(Rack::Request, post?: true, get?: false)
          response_body = { 'error' => { 'message' => 'Method not found', 'code' => -32601 } }.to_json
          response = [400, {}, [response_body]]

          server_with_logger.send(:log_http_response, request, response)

          log_content = File.read(log_file.path)
          parsed_log = JSON.parse(log_content.lines.first)
          expect(parsed_log['level']).to eq('ERROR')
          expect(parsed_log['message']).to eq('HTTP Response error: Method not found')
          expect(parsed_log['context']['error_code']).to eq(-32601)
        end
      end

      context 'with POST response containing accepted (SSE)' do
        it 'logs SSE stream response' do
          request = instance_double(Rack::Request, post?: true, get?: false)
          response_body = { 'accepted' => true }.to_json
          response = [202, {}, [response_body]]

          server_with_logger.send(:log_http_response, request, response)

          log_content = File.read(log_file.path)
          parsed_log = JSON.parse(log_content.lines.first)
          expect(parsed_log['level']).to eq('INFO')
          expect(parsed_log['message']).to eq('Response sent via SSE stream')
        end
      end

      context 'with POST response containing success' do
        it 'logs success with id and session_id' do
          request = instance_double(Rack::Request, post?: true, get?: false)
          response_body = { 'id' => 42, 'result' => {} }.to_json
          headers = { 'Mcp-Session-Id' => 'sess-456' }
          response = [200, headers, [response_body]]

          server_with_logger.send(:log_http_response, request, response)

          log_content = File.read(log_file.path)
          parsed_log = JSON.parse(log_content.lines.first)
          expect(parsed_log['level']).to eq('INFO')
          expect(parsed_log['message']).to eq('HTTP Response: success (id: 42)')
          expect(parsed_log['context']['id']).to eq(42)
          expect(parsed_log['context']['session_id']).to eq('sess-456')
        end
      end

      context 'with POST response containing invalid JSON' do
        it 'logs a warning' do
          request = instance_double(Rack::Request, post?: true, get?: false)
          response = [200, {}, ['not json{{']]

          server_with_logger.send(:log_http_response, request, response)

          log_content = File.read(log_file.path)
          parsed_log = JSON.parse(log_content.lines.first)
          expect(parsed_log['level']).to eq('WARN')
          expect(parsed_log['message']).to eq('Invalid JSON in HTTP response')
        end
      end

      context 'with GET response and 200 status' do
        it 'logs SSE stream established' do
          request = instance_double(Rack::Request, post?: false, get?: true)
          response = [200, {}, []]

          server_with_logger.send(:log_http_response, request, response)

          log_content = File.read(log_file.path)
          parsed_log = JSON.parse(log_content.lines.first)
          expect(parsed_log['level']).to eq('INFO')
          expect(parsed_log['message']).to eq('SSE stream established')
        end
      end

      context 'with empty body on POST' do
        it 'does not log response details' do
          request = instance_double(Rack::Request, post?: true, get?: false)
          response = [200, {}, []]

          server_with_logger.send(:log_http_response, request, response)

          expect(File.read(log_file.path)).to be_empty
        end
      end

      context 'with non-array body' do
        it 'does not log response details' do
          request = instance_double(Rack::Request, post?: true, get?: false)
          response = [200, {}, 'string body']

          server_with_logger.send(:log_http_response, request, response)

          expect(File.read(log_file.path)).to be_empty
        end
      end

      context 'with no logger' do
        it 'returns nil immediately' do
          request = instance_double(Rack::Request)
          response = [200, {}, []]
          expect(server_without_logger.send(:log_http_response, request, response)).to be_nil
        end
      end
    end
  end
end
