# frozen_string_literal: true

require 'msf/core/mcp'
require 'stringio'

RSpec.describe Msf::MCP::Logging::Sinks::Sanitizing do
  # Use a StringIO-backed Stream as the inner sink so we can inspect output
  # without touching the filesystem.
  let(:buffer)     { StringIO.new }
  let(:inner_sink) { Rex::Logging::Sinks::Stream.new(buffer) }
  let(:sink)       { described_class.new(inner_sink) }

  def logged_output
    buffer.string
  end

  describe '#log' do
    it 'passes through innocuous messages unchanged' do
      sink.log(Rex::Logging::LOG_INFO, 'msfmcp', 0, 'connected to host')
      expect(logged_output).to include('connected to host')
    end

    it 'delegates severity, source, and level to the inner sink' do
      sink.log(Rex::Logging::LOG_WARN, 'msfmcp', 0, 'watch out')
      expect(logged_output).to match(/\[w\(0\)\].*msfmcp.*watch out/)
    end

    it 'redacts password key-value pairs' do
      sink.log(Rex::Logging::LOG_INFO, 'msfmcp', 0, 'password: hunter2')
      expect(logged_output).to include('[REDACTED]')
      expect(logged_output).not_to include('hunter2')
    end

    it 'redacts token key-value pairs' do
      sink.log(Rex::Logging::LOG_INFO, 'msfmcp', 0, 'token=abc123xyz')
      expect(logged_output).to include('[REDACTED]')
      expect(logged_output).not_to include('abc123xyz')
    end

    it 'redacts bearer tokens' do
      sink.log(Rex::Logging::LOG_INFO, 'msfmcp', 0, 'Authorization: Bearer eyJhbGci.payload.sig')
      expect(logged_output).to include('[REDACTED]')
      expect(logged_output).not_to include('eyJhbGci.payload.sig')
    end

    it 'redacts API keys' do
      sink.log(Rex::Logging::LOG_INFO, 'msfmcp', 0, 'api_key=sk_live_1234567890abcdef')
      expect(logged_output).to include('[REDACTED]')
      expect(logged_output).not_to include('sk_live_1234567890abcdef')
    end

    it 'passes through non-string messages without error' do
      expect { sink.log(Rex::Logging::LOG_INFO, 'msfmcp', 0, nil) }.not_to raise_error
    end
  end

  describe '#cleanup' do
    it 'delegates cleanup to the inner sink' do
      expect(inner_sink).to receive(:cleanup)
      sink.cleanup
    end
  end
end
