# frozen_string_literal: true

require 'msf/core/mcp'
require 'json'
require 'tempfile'

RSpec.describe Msf::MCP::Logging::Logger do
  let(:log_file) { Tempfile.new('test_log').path }

  describe 'initialization' do
    it 'creates logger' do
      logger = described_class.new(log_file: log_file)
      expect(logger.log_file).to eq(log_file)
    end
  end

  describe '#log_error' do
    let(:logger) { described_class.new(log_file: log_file) }
    let(:exception) { StandardError.new('Test error message') }

    it 'writes error to log file' do
      logger.log_error(
        exception: exception,
        message: 'Operation failed',
        context: { tool: 'search_modules', query: 'test' }
      )

      log_content = File.read(log_file)
      expect(log_content).not_to be_empty

      log_entry = JSON.parse(log_content)
      expect(log_entry['level']).to eq('ERROR')
      expect(log_entry['message']).to eq('Operation failed')
      expect(log_entry['exception']['class']).to eq('StandardError')
      expect(log_entry['exception']['message']).to eq('Test error message')
      expect(log_entry['context']['tool']).to eq('search_modules')
    end

    it 'includes timestamp in ISO 8601 format' do
      logger.log_error(exception: exception, message: 'Test', context: {})

      log_entry = JSON.parse(File.read(log_file))
      expect(log_entry['timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)
    end

    it 'includes exception backtrace (first 5 lines)' do
      begin
        raise StandardError, 'Test error'
      rescue StandardError => e
        logger.log_error(exception: e, message: 'Test', context: {})
      end

      log_entry = JSON.parse(File.read(log_file))
      expect(log_entry['exception']['backtrace']).to be_an(Array)
      expect(log_entry['exception']['backtrace'].size).to be <= 5
    end

    it 'does not include error_type when exception does not respond to error_type' do
      logger.log_error(exception: exception, message: 'Test', context: {})

      log_entry = JSON.parse(File.read(log_file))
      expect(log_entry['exception']).not_to have_key('type')
    end

    it 'does not include original_error when exception does not respond to original_error' do
      logger.log_error(exception: exception, message: 'Test', context: {})

      log_entry = JSON.parse(File.read(log_file))
      expect(log_entry).not_to have_key('original_error')
    end
  end

  describe '#sanitize_for_log' do
    let(:logger) { described_class.new(log_file: log_file) }

    it 'redacts password fields' do
      data = { username: 'admin', password: 'secret123' }
      sanitized = logger.sanitize_for_log(data)

      expect(sanitized[:password]).to eq('[REDACTED]')
      expect(sanitized[:username]).to eq('admin')
    end

    it 'redacts token fields by key name' do
      data = { token: 'abc123xyz', host: 'localhost' }
      sanitized = logger.sanitize_for_log(data)

      expect(sanitized[:token]).to eq('[REDACTED]')
      expect(sanitized[:host]).to eq('localhost')
    end

    it 'redacts secret fields by key name' do
      data = { secret: 'my_secret', api_key: 'key123', api_secret: 's3cret' }
      sanitized = logger.sanitize_for_log(data)

      expect(sanitized[:secret]).to eq('[REDACTED]')
      expect(sanitized[:api_key]).to eq('[REDACTED]')
      expect(sanitized[:api_secret]).to eq('[REDACTED]')
    end

    it 'redacts sensitive keys regardless of case' do
      data = { 'Password' => 'secret', 'TOKEN' => 'abc' }
      sanitized = logger.sanitize_for_log(data)

      expect(sanitized['Password']).to eq('[REDACTED]')
      expect(sanitized['TOKEN']).to eq('[REDACTED]')
    end

    it 'redacts token fields in strings' do
      str = 'Authorization: token abc123xyz'
      sanitized = logger.send(:sanitize_string, str)

      expect(sanitized).to include('[REDACTED]')
      expect(sanitized).not_to include('abc123xyz')
    end

    it 'redacts API keys in strings' do
      str = 'api_key=sk_live_1234567890abcdef'
      sanitized = logger.send(:sanitize_string, str)

      expect(sanitized).to include('[REDACTED]')
      expect(sanitized).not_to include('sk_live_1234567890abcdef')
    end

    it 'redacts Bearer tokens' do
      str = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
      sanitized = logger.send(:sanitize_string, str)

      expect(sanitized).to include('[REDACTED]')
      expect(sanitized).not_to include('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')
    end

    it 'recursively sanitizes nested hashes' do
      data = {
        request: {
          auth: { token: 'secret_token', user: 'admin' },
          params: { query: 'test' },
          credential: { password: 'mypass', user: 'myuser' }
        }
      }

      sanitized = logger.sanitize_for_log(data)
      expect(sanitized[:request][:auth][:token]).to eq('[REDACTED]')
      expect(sanitized[:request][:auth][:user]).to eq('admin')
      expect(sanitized[:request][:params][:query]).to eq('test')
      expect(sanitized[:request][:credential][:password]).to eq('[REDACTED]')
      expect(sanitized[:request][:credential][:user]).to eq('myuser')
    end

    it 'recursively sanitizes arrays' do
      data = [
        { password: 'secret1', user: 'a' },
        { password: 'secret2', user: 'b' }
      ]

      sanitized = logger.sanitize_for_log(data)
      expect(sanitized).to be_an(Array)
      expect(sanitized.size).to eq(2)
      expect(sanitized[0][:password]).to eq('[REDACTED]')
      expect(sanitized[0][:user]).to eq('a')
      expect(sanitized[1][:password]).to eq('[REDACTED]')
      expect(sanitized[1][:user]).to eq('b')
    end

    it 'handles non-string, non-hash, non-array values' do
      expect(logger.sanitize_for_log(123)).to eq(123)
      expect(logger.sanitize_for_log(true)).to eq(true)
      expect(logger.sanitize_for_log(nil)).to be_nil
    end
  end

  describe 'sensitive data patterns' do
    let(:logger) { described_class.new(log_file: log_file) }

    it 'redacts password in various formats' do
      [
        'password: secret123',
        'password=secret123',
        '"password":"secret123"',
        "password='secret123'"
      ].each do |str|
        sanitized = logger.send(:sanitize_string, str)
        expect(sanitized).to include('[REDACTED]'), "Failed for: #{str}"
        expect(sanitized).not_to include('secret123'), "Failed for: #{str}"
      end
    end

    it 'redacts secrets in various formats' do
      str = 'secret_key: my_secret_value'
      sanitized = logger.send(:sanitize_string, str)

      expect(sanitized).to include('[REDACTED]')
      expect(sanitized).not_to include('my_secret_value')
    end
  end

  describe 'log level filtering' do
    let(:test_log_file) { Tempfile.new('level_test_log').path }
    let(:logger) { described_class.new(log_file: test_log_file, log_level: 'WARN') }

    before do
      # Clean up any existing log file
      File.delete(test_log_file) if File.exist?(test_log_file)
    end

    it 'filters out DEBUG messages when level is WARN' do
      logger.log(level: 'DEBUG', message: 'Debug message', context: {})

      expect(File.exist?(test_log_file)).to be false  # No log written
    end

    it 'filters out INFO messages when level is WARN' do
      logger.log(level: 'INFO', message: 'Info message', context: {})

      expect(File.exist?(test_log_file)).to be false  # No log written
    end

    it 'allows WARN messages when level is WARN' do
      logger.log(level: 'WARN', message: 'Warning message', context: {})

      log_entry = JSON.parse(File.read(test_log_file))
      expect(log_entry['level']).to eq('WARN')
      expect(log_entry['message']).to eq('Warning message')
    end

    it 'allows ERROR messages when level is WARN' do
      logger.log(level: 'ERROR', message: 'Error message', context: {})

      log_entry = JSON.parse(File.read(test_log_file))
      expect(log_entry['level']).to eq('ERROR')
    end

    it 'allows FATAL messages when level is WARN' do
      logger.log(level: 'FATAL', message: 'Fatal message', context: {})

      log_entry = JSON.parse(File.read(test_log_file))
      expect(log_entry['level']).to eq('FATAL')
    end

    it 'defaults to INFO level when invalid level provided' do
      invalid_logger = described_class.new(log_file: test_log_file, log_level: 'INVALID')

      # DEBUG should be filtered with INFO level
      invalid_logger.log(level: 'DEBUG', message: 'Debug', context: {})
      expect(File.exist?(test_log_file)).to be false

      # INFO should pass with INFO level
      invalid_logger.log(level: 'INFO', message: 'Info', context: {})
      expect(File.exist?(test_log_file)).to be true
    end
  end

  describe 'error handling' do
    it 'handles file write failures gracefully' do
      logger = described_class.new(log_file: '/invalid/path/that/does/not/exist.log')
      exception = StandardError.new('Test')

      # Should not raise, but warn to stderr
      expect do
        logger.log_error(exception: exception, message: 'Test', context: {})
      end.not_to raise_error
    end
  end
end
