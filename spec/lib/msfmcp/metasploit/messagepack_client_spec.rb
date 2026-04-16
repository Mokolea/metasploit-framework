# frozen_string_literal: true

require 'msfmcp'

RSpec.describe MsfMcp::Metasploit::MessagePackClient do
  let(:host) { 'localhost' }
  let(:port) { 55553 }
  let(:client) { described_class.new(host: host, port: port) }

  describe '#initialize' do
    it 'sets instance variables' do
      expect(client.instance_variable_get(:@host)).to eq(host)
      expect(client.instance_variable_get(:@port)).to eq(port)
      expect(client.instance_variable_get(:@endpoint)).to eq('/api/')
      expect(client.instance_variable_get(:@token)).to be_nil
    end

    it 'defaults ssl to true when not specified' do
      expect(client.instance_variable_get(:@ssl)).to eq(true)
    end

    it 'accepts ssl parameter' do
      client_no_ssl = described_class.new(host: host, port: port, ssl: false)
      expect(client_no_ssl.instance_variable_get(:@ssl)).to eq(false)
    end
  end

  describe 'SSL configuration' do
    let(:http_mock) { instance_double(Net::HTTP) }

    before do
      allow(Net::HTTP).to receive(:new).and_return(http_mock)
      allow(http_mock).to receive(:use_ssl=)
      allow(http_mock).to receive(:verify_mode=)
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: { 'result' => 'success', 'token' => 'test123' }.to_msgpack)
      )
    end

    context 'when ssl is true' do
      let(:client) { described_class.new(host: host, port: port, ssl: true) }

      it 'enables SSL on Net::HTTP client' do
        expect(http_mock).to receive(:use_ssl=).with(true)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end

      it 'sets verify_mode to VERIFY_NONE' do
        expect(http_mock).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end
    end

    context 'when ssl is false' do
      let(:client) { described_class.new(host: host, port: port, ssl: false) }

      it 'disables SSL on Net::HTTP client' do
        expect(http_mock).to receive(:use_ssl=).with(false)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end

      it 'does not set verify_mode' do
        expect(http_mock).not_to receive(:verify_mode=)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end
    end

    context 'with default SSL setting' do
      it 'uses SSL by default' do
        expect(http_mock).to receive(:use_ssl=).with(true)
        expect(http_mock).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end
    end

    context 'when explicitly set to true' do
      let(:client) { described_class.new(host: host, port: port, ssl: true) }

      it 'configures HTTPS connection' do
        expect(http_mock).to receive(:use_ssl=).with(true)
        expect(http_mock).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
        client.send(:send_request, ['auth.login', 'user', 'pass'])
      end
    end
  end

  describe '#authenticate' do
    it 'sends authentication request with username and password' do
      expect(client).to receive(:send_request).with(['auth.login', 'testuser', 'testpass']).and_return({ 'result' => 'success', 'token' => 'abc123' })

      client.authenticate('testuser', 'testpass')
    end

    it 'stores token from response' do
      allow(client).to receive(:send_request).and_return({ 'result' => 'success', 'token' => 'abc123' })
      token = client.authenticate('testuser', 'testpass')
      expect(token).to eq('abc123')
    end

    it 'raises AuthenticationError on failure' do
      # send_request raises AuthenticationError for HTTP 401
      allow(client).to receive(:send_request).and_raise(MsfMcp::Metasploit::AuthenticationError, 'Login Failed')

      expect {
        client.authenticate('testuser', 'testpass')
      }.to raise_error(MsfMcp::Metasploit::AuthenticationError, 'Login Failed')
    end

    it 'raises AuthenticationError with default message when result is not success' do
      # send_request raises AuthenticationError for HTTP 401
      allow(client).to receive(:send_request).and_raise(MsfMcp::Metasploit::AuthenticationError, 'Login Failed')

      expect {
        client.authenticate('testuser', 'testpass')
      }.to raise_error(MsfMcp::Metasploit::AuthenticationError, 'Login Failed')
    end
  end

  describe '#call_api' do
    before do
      client.instance_variable_set(:@token, 'abc123')
      allow(client).to receive(:send_request).and_return(['module1', 'module2'])
    end

    it 'sends method call with token and arguments' do
      expect(client).to receive(:send_request).with(['module.search', 'abc123', 'smb']).and_return([])

      client.call_api('module.search', ['smb'])
    end

    it 'returns result from response' do
      result = client.call_api('module.search', ['smb'])
      expect(result).to eq(['module1', 'module2'])
    end

    it 'raises ArgumentError when args is not an Array' do
      expect {
        client.call_api('module.search', 'smb')
      }.to raise_error(ArgumentError, /args must be an Array/)
    end

    it 'raises ArgumentError when args is a Hash' do
      expect {
        client.call_api('module.search', { query: 'smb' })
      }.to raise_error(ArgumentError, /args must be an Array/)
    end

    it 'raises AuthenticationError if no token present' do
      client.instance_variable_set(:@token, nil)

      expect {
        client.call_api('module.search', ['smb'])
      }.to raise_error(MsfMcp::Metasploit::AuthenticationError, "Unable to authenticate after 0 attempts: Not authenticated")
    end

    it 'raises APIError when response contains error' do
      # send_request raises APIError for HTTP 500
      allow(client).to receive(:send_request).and_raise(MsfMcp::Metasploit::APIError, 'Method not found')

      expect {
        client.call_api('module.search', ['smb'])
      }.to raise_error(MsfMcp::Metasploit::APIError, 'Method not found')
    end

    it 'raises APIError with error value when error is not a string' do
      # send_request raises APIError for HTTP 500
      allow(client).to receive(:send_request).and_raise(MsfMcp::Metasploit::APIError, 'true')

      expect {
        client.call_api('module.search', ['smb'])
      }.to raise_error(MsfMcp::Metasploit::APIError, 'true')
    end
  end

  describe '#shutdown' do
    it 'clears token from memory' do
      client.instance_variable_set(:@token, 'abc123')
      client.shutdown
      expect(client.instance_variable_get(:@token)).to be_nil
    end

    it 'clears stored credentials' do
      client.instance_variable_set(:@user, 'testuser')
      client.instance_variable_set(:@password, 'testpass')
      client.shutdown
      expect(client.instance_variable_get(:@user)).to be_nil
      expect(client.instance_variable_get(:@password)).to be_nil
    end

    it 'finishes HTTP connection if started' do
      http_mock = double('Net::HTTP')
      allow(http_mock).to receive(:started?).and_return(true)
      allow(http_mock).to receive(:finish)

      client.instance_variable_set(:@http, http_mock)
      client.shutdown

      expect(http_mock).to have_received(:finish)
    end
  end

  describe '#sanitize_request_array' do
    it 'redacts password in auth.login requests' do
      result = client.send(:sanitize_request_array, ['auth.login', 'admin', 's3cret'])
      expect(result).to eq(['auth.login', 'admin', '[REDACTED]'])
    end

    it 'redacts token in API call requests' do
      result = client.send(:sanitize_request_array, ['module.search', 'tok_abc123', 'smb'])
      expect(result).to eq(['module.search', '[REDACTED]', 'smb'])
    end

    it 'does not mutate the original array' do
      original = ['auth.login', 'admin', 's3cret']
      client.send(:sanitize_request_array, original)
      expect(original).to eq(['auth.login', 'admin', 's3cret'])
    end

    it 'handles single-element arrays' do
      result = client.send(:sanitize_request_array, ['auth.logout'])
      expect(result).to eq(['auth.logout'])
    end
  end

  describe 'debug logging' do
    let(:logger) { instance_double(MsfMcp::Logging::Logger) }
    let(:client_with_logger) do
      described_class.new(host: host, port: port, ssl: false, logger: logger)
    end
    let(:http_mock) { instance_double(Net::HTTP) }

    before do
      allow(Net::HTTP).to receive(:new).and_return(http_mock)
      allow(http_mock).to receive(:use_ssl=)
    end

    it 'logs request and response at DEBUG level via authenticate' do
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: { 'result' => 'success', 'token' => 'abc' }.to_msgpack)
      )

      expect(logger).to receive(:log).with(
        level: 'DEBUG',
        message: 'MessagePack request',
        context: hash_including(body: ['auth.login', 'user', '[REDACTED]'])
      )
      expect(logger).to receive(:log).with(
        level: 'DEBUG',
        message: 'MessagePack response',
        context: hash_including(:status, :body)
      )

      client_with_logger.authenticate('user', 'pass')
    end

    it 'logs request and response at DEBUG level via call_api' do
      # Authenticate first to get a token
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: { 'result' => 'success', 'token' => 'abc' }.to_msgpack)
      )
      allow(logger).to receive(:log)
      client_with_logger.authenticate('user', 'pass')

      # Now set up the call_api response
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: { 'modules' => [] }.to_msgpack)
      )

      expect(logger).to receive(:log).with(
        level: 'DEBUG',
        message: 'MessagePack request',
        context: hash_including(body: ['module.search', '[REDACTED]', 'smb'])
      )
      expect(logger).to receive(:log).with(
        level: 'DEBUG',
        message: 'MessagePack response',
        context: hash_including(:status, :body)
      )

      client_with_logger.call_api('module.search', ['smb'])
    end

    it 'does not error when logger is nil via authenticate' do
      client_no_ssl = described_class.new(host: host, port: port, ssl: false)
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: { 'result' => 'success', 'token' => 'abc' }.to_msgpack)
      )

      expect { client_no_ssl.authenticate('user', 'pass') }.not_to raise_error
    end

    it 'does not error when logger is nil via call_api' do
      client_no_ssl = described_class.new(host: host, port: port, ssl: false)
      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: { 'result' => 'success', 'token' => 'abc' }.to_msgpack)
      )
      client_no_ssl.authenticate('user', 'pass')

      allow(http_mock).to receive(:request).and_return(
        instance_double(Net::HTTPResponse, code: '200', body: { 'modules' => [] }.to_msgpack)
      )

      expect { client_no_ssl.call_api('module.search', ['smb']) }.not_to raise_error
    end
  end

  describe 'automatic re-authentication' do
    before do
      # Initial authentication
      allow(client).to receive(:send_request).with(['auth.login', 'testuser', 'testpass']).and_return(
        { 'result' => 'success', 'token' => 'initial_token' }
      )

      client.authenticate('testuser', 'testpass')
    end

    it 'automatically re-authenticates on invalid token error' do
      call_count = 0

      allow(client).to receive(:send_request) do |request_array|
        call_count += 1

        case call_count
        when 1
          # First API call raises AuthenticationError (simulating HTTP 401)
          raise MsfMcp::Metasploit::AuthenticationError, 'Invalid token'
        when 2
          # Re-authentication request succeeds
          { 'result' => 'success', 'token' => 'refreshed_token' }
        when 3
          # Retry with new token succeeds
          { 'modules' => [] }
        else
          raise 'Unexpected request sequence'
        end
      end

      result = client.search_modules('smb')
      expect(result).to eq({ 'modules' => [] })
      expect(client.instance_variable_get(:@token)).to eq('refreshed_token')
    end

    it 'does not retry more than once' do
      retry_attempt = 0

      allow(client).to receive(:send_request) do |request_array|
        if request_array[0] == 'auth.login'
          # Re-authentication succeeds
          { 'result' => 'success', 'token' => 'new_token' }
        else
          # Always raise AuthenticationError for API calls
          retry_attempt += 1
          raise MsfMcp::Metasploit::AuthenticationError, 'Invalid token'
        end
      end

      # Should fail after one retry attempt
      expect {
        client.search_modules('smb')
      }.to raise_error(MsfMcp::Metasploit::AuthenticationError, /Unable to authenticate/)

      # Should have tried: initial call + re-auth + retry = 2 API calls (not counting auth)
      expect(retry_attempt).to eq(2)
    end

    it 'does not auto-reauth if credentials not stored' do
      # Create new client without authenticating
      new_client = described_class.new(host: host, port: port)
      new_client.instance_variable_set(:@token, 'some_token')

      allow(new_client).to receive(:send_request).and_raise(MsfMcp::Metasploit::AuthenticationError, 'Invalid token')

      expect {
        new_client.search_modules('smb')
      }.to raise_error(MsfMcp::Metasploit::AuthenticationError, /Unable to authenticate/)
    end

    it 'resets retry count after successful re-authentication' do
      call_sequence = []

      allow(client).to receive(:send_request) do |request_array|
        if request_array[0] == 'module.search'
          if call_sequence.count { |c| c == :search_call } == 0
            call_sequence << :search_call
            # First search call fails
            raise MsfMcp::Metasploit::AuthenticationError, 'Invalid token'
          else
            call_sequence << :search_retry
            # Retry succeeds
            { 'modules' => ['mod1'] }
          end
        elsif request_array[0] == 'auth.login'
          call_sequence << :reauth
          { 'result' => 'success', 'token' => "token#{call_sequence.length}" }
        elsif request_array[0] == 'db.hosts'
          if call_sequence.count { |c| c == :hosts_call } == 0
            call_sequence << :hosts_call
            # First hosts call fails
            raise MsfMcp::Metasploit::AuthenticationError, 'Invalid token'
          else
            call_sequence << :hosts_retry
            # Retry succeeds
            { 'hosts' => [] }
          end
        else
          raise "Unexpected request: #{request_array[0]}"
        end
      end

      # First call with auto-reauth
      result1 = client.search_modules('smb')
      expect(result1).to eq({ 'modules' => ['mod1'] })

      # Second call with auto-reauth (retry count should have been reset)
      result2 = client.db_hosts({})
      expect(result2).to eq({ 'hosts' => [] })

      # Verify the sequence: search fail, reauth, search retry, hosts fail, reauth, hosts retry
      expect(call_sequence).to eq([:search_call, :reauth, :search_retry, :hosts_call, :reauth, :hosts_retry])
    end
  end
end
