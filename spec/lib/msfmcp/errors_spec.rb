# frozen_string_literal: true

require 'msfmcp'

RSpec.describe MsfMcp::Error do
  describe 'inheritance' do
    it 'inherits from StandardError' do
      expect(described_class).to be < StandardError
    end

    it 'can be rescued as StandardError' do
      expect do
        raise described_class, 'test'
      end.to raise_error(StandardError)
    end
  end
end

RSpec.describe MsfMcp::MCP::ValidationError do
  describe 'inheritance' do
    it 'inherits from MsfMcp::Error' do
      expect(described_class).to be < MsfMcp::Error
    end
  end
end

RSpec.describe MsfMcp::MCP::ConfigurationError do
  describe 'inheritance' do
    it 'inherits from MsfMcp::Error' do
      expect(described_class).to be < MsfMcp::Error
    end
  end
end

RSpec.describe MsfMcp::MCP::ToolExecutionError do
  describe 'inheritance' do
    it 'inherits from MsfMcp::Error' do
      expect(described_class).to be < MsfMcp::Error
    end
  end
end

RSpec.describe MsfMcp::Metasploit::AuthenticationError do
  describe 'inheritance' do
    it 'inherits from MsfMcp::Error' do
      expect(described_class).to be < MsfMcp::Error
    end
  end
end

RSpec.describe MsfMcp::Metasploit::ConnectionError do
  describe 'inheritance' do
    it 'inherits from MsfMcp::Error' do
      expect(described_class).to be < MsfMcp::Error
    end
  end
end

RSpec.describe MsfMcp::Metasploit::APIError do
  describe 'inheritance' do
    it 'inherits from MsfMcp::Error' do
      expect(described_class).to be < MsfMcp::Error
    end
  end
end

RSpec.describe MsfMcp::Metasploit::RpcStartupError do
  describe 'inheritance' do
    it 'inherits from MsfMcp::Error' do
      expect(described_class).to be < MsfMcp::Error
    end
  end
end
