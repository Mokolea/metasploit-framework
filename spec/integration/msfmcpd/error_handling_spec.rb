# frozen_string_literal: true

require 'msfmcp'
require 'webmock/rspec'

RSpec.describe 'Error Handling Integration' do
  # Disable real HTTP connections for integration tests
  before(:all) do
    WebMock.disable_net_connect!(allow_localhost: false)
  end

  after(:all) do
    WebMock.allow_net_connect!
  end

  let(:host) { 'localhost' }
  let(:port) { 55553 }

  describe 'MessagePack Error Handling' do
    let(:endpoint) { '/api/' }
    let(:api_url) { "https://#{host}:#{port}#{endpoint}" }
    let(:client) do
      MsfMcp::Metasploit::Client.new(
        api_type: 'messagepack',
        host: host,
        port: port,
        endpoint: endpoint,
        ssl: true
      )
    end

    before do
      # Mock successful authentication to get the token
      stub_request(:post, api_url)
        .with(body: ['auth.login', 'user', 'pass'].to_msgpack)
        .to_return(
          status: 200,
          body: { 'result' => 'success', 'token' => 'test_token' }.to_msgpack,
          headers: { 'Content-Type' => 'binary/message-pack' }
        )

      client.authenticate('user', 'pass')
    end

    describe 'Network Connection Failures' do
      it 'converts Errno::ECONNREFUSED to ConnectionError' do
        # Mock a connection refused error
        stub_request(:post, api_url)
          .with(body: ['module.search', 'test_token', 'smb'].to_msgpack)
          .to_raise(Errno::ECONNREFUSED)

        expect { client.search_modules('smb') }.to raise_error(MsfMcp::Metasploit::ConnectionError, /Cannot connect to Metasploit RPC/)
      end

      it 'converts SocketError to ConnectionError' do
        stub_request(:post, api_url)
          .to_raise(SocketError.new('getaddrinfo: Name or service not known'))

        expect { client.search_modules('smb') }.to raise_error(MsfMcp::Metasploit::ConnectionError, /Network error/)
      end

      it 'converts Timeout::Error to ConnectionError' do
        # Timeout on search
        stub_request(:post, api_url)
          .with(body: ['module.search', 'test_token', 'smb'].to_msgpack)
          .to_raise(Timeout::Error.new('execution expired'))

        expect { client.search_modules('smb') }.to raise_error(MsfMcp::Metasploit::ConnectionError, /Request timeout/)
      end

      it 'converts EOFError to ConnectionError' do
        stub_request(:post, api_url)
          .to_raise(EOFError.new('end of file reached'))

        expect { client.search_modules('smb') }.to raise_error(MsfMcp::Metasploit::ConnectionError, /Empty response/)
      end
    end

    describe 'HTTP Status Code Handling' do
      it 'converts HTTP 401 to AuthenticationError' do
        # Reauthenticate with invalid creds
        stub_request(:post, api_url)
          .to_return(
            status: 401,
            body: { 'error_message' => 'Invalid credentials' }.to_msgpack,
            headers: { 'Content-Type' => 'binary/message-pack' }
          )

        expect { client.authenticate('invalid', 'invalid') }.to raise_error(MsfMcp::Metasploit::AuthenticationError, /Invalid credentials/)
      end

      it 'converts HTTP 500 to APIError' do
        # Server error on API call
        stub_request(:post, api_url)
          .with(body: ['module.search', 'test_token', 'smb'].to_msgpack)
          .to_return(
            status: 500,
            body: { 'error_message' => 'Internal server error' }.to_msgpack
          )

        expect { client.search_modules('smb') }.to raise_error(MsfMcp::Metasploit::APIError, /Internal server error/)
      end

      it 'converts unexpected HTTP status to ConnectionError' do
        stub_request(:post, api_url)
          .to_return(status: 503, body: 'Service Unavailable')

        expect { client.search_modules('smb') }.to raise_error(MsfMcp::Metasploit::ConnectionError, /HTTP 503/)
      end
    end

    describe 'Tool Error Handling Integration' do
      let(:rate_limiter) { MsfMcp::Security::RateLimiter.new(requests_per_minute: 60) }
      let(:server_context) do
        {
          msf_client: client,
          rate_limiter: rate_limiter,
          config: {}
        }
      end

      it 'converts Metasploit errors to MCP errors end-to-end' do
        # Test that errors propagate correctly through the entire stack:
        # HTTP error → Metasploit exception → MCP exception
        stub_request(:post, api_url)
          .with(body: ['module.search', 'test_token', 'smb'].to_msgpack)
          .to_return(
            status: 401,
            body: { 'error_message' => 'Token invalid' }.to_msgpack
          )

        expect {
          MsfMcp::MCPTools::SearchModules.call(query: 'smb', server_context: server_context)
        }.to raise_error(MsfMcp::MCP::ToolExecutionError, /Authentication failed/)
      end
    end
  end

  describe 'JSON-RPC Error Handling' do
    let(:jsonrpc_url) { "https://#{host}:#{port}/api/v1/json-rpc" }
    let(:client) do
      MsfMcp::Metasploit::Client.new(
        api_type: 'json-rpc',
        host: host,
        port: port,
        endpoint: '/api/v1/json-rpc',
        token: 'bearer_token',
        ssl: true
      )
    end

    it 'handles JSON-RPC error responses' do
      stub_request(:post, jsonrpc_url)
        .to_return(
          status: 200,
          body: {
            jsonrpc: '2.0',
            error: { code: -32601, message: 'Method not found' },
            id: 1
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      expect { client.search_modules('smb') }.to raise_error(MsfMcp::Metasploit::APIError, /Method not found/)
    end

    it 'handles network errors with JSON-RPC client' do
      stub_request(:post, jsonrpc_url)
        .to_raise(Errno::ECONNREFUSED)

      expect { client.search_modules('smb') }.to raise_error(MsfMcp::Metasploit::ConnectionError)
    end

    it 'raises error with invalid bearer token' do
      stub_request(:post, jsonrpc_url)
        .to_return(
          status: 401,
          body: { 'error' => 'Unauthorized' }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      expect { client.search_modules('smb') }.to raise_error(MsfMcp::Metasploit::AuthenticationError, /Invalid authentication token/)
    end
  end
end
