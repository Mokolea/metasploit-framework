# frozen_string_literal: true

require 'msfmcp'

RSpec.describe MsfMcp::MCPTools::ModuleInfo do
  let(:msf_client) { double('MsfMcp::Metasploit::Client') }
  let(:rate_limiter) { double('MsfMcp::Security::RateLimiter') }
  let(:server_context) do
    {
      msf_client: msf_client,
      rate_limiter: rate_limiter,
      config: {}
    }
  end

  let(:msf_response) do
    {
      'name' => 'ms17_010_eternalblue',
      'fullname' => 'exploit/windows/smb/ms17_010_eternalblue',
      'type' => 'exploit',
      'rank' => 'excellent',
      'description' => 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption',
      'license' => 'Metasploit Framework License (BSD)',
      'filepath' => '/usr/share/metasploit-framework/modules/exploits/windows/smb/ms17_010_eternalblue.rb',
      'arch' => ['x86', 'x64'],
      'platform' => ['Windows'],
      'authors' => ['sleepya', 'zerosum0x0'],
      'references' => [
        ['CVE', '2017-0143'],
        ['MSB', 'MS17-010']
      ]
    }
  end

  before do
    allow(rate_limiter).to receive(:check_rate_limit!)
    allow(msf_client).to receive(:module_info).and_return(msf_response)
  end

  describe 'Tool Name' do
    it 'has the correct tool name' do
      expect(described_class.tool_name).to eq('msf_module_info')
    end
  end

  describe 'Input Schema Validation' do
    it 'defines type and name as required parameters' do
      input_schema = described_class.input_schema
      expect(input_schema.schema[:required]).to include("type", "name")
    end

    it 'defines type as enum with valid module types' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:type][:type]).to eq('string')
      expect(properties[:type][:enum]).to include('exploit', 'auxiliary', 'post', 'payload')
    end

    it 'defines name as string type' do
      properties = described_class.input_schema.schema[:properties]
      expect(properties[:name][:type]).to eq('string')
    end
  end

  describe 'Output Schema' do
    it 'returns complete module details' do
      output_schema = described_class.output_schema.schema
      data_properties = output_schema[:properties][:data][:properties]

      expect(data_properties[:type]).to eq({ type: 'string' })
      expect(data_properties[:name]).to eq({ type: 'string' })
      expect(data_properties[:fullname]).to eq({ type: 'string' })
      expect(data_properties[:description]).to eq({ type: 'string' })
      expect(data_properties[:rank]).to eq({ type: 'string' })
      expect(data_properties[:authors]).to eq({ type: 'array', items: { type: 'string' } })
      expect(data_properties[:platforms]).to eq({ type: 'array', items: { type: 'string' } })
      expect(data_properties[:architectures]).to eq({ type: 'array', items: { type: 'string', enum: %w[
        x86 x86_64 x64 mips mipsle mipsbe mips64 mips64le ppc ppce500v2
        ppc64 ppc64le cbea cbea64 sparc sparc64 armle armbe aarch64 cmd
        php tty java ruby dalvik python nodejs firefox zarch r
        riscv32be riscv32le riscv64be riscv64le loongarch64
      ] } })
    end

    it 'includes options object with configuration parameters' do
      data_properties = described_class.output_schema.schema[:properties][:data][:properties]
      expect(data_properties[:options]).to eq({ type: 'object' })
      expect(data_properties[:default_options]).to eq({ type: 'object' })
    end

    it 'includes targets object for exploit modules' do
      data_properties = described_class.output_schema.schema[:properties][:data][:properties]
      expect(data_properties[:targets]).to eq({ type: 'object' })
      expect(data_properties[:default_target]).to eq({ type: 'integer' })
    end

    it 'includes references array with CVE, MSB, URL refs' do
      data_properties = described_class.output_schema.schema[:properties][:data][:properties]
      expect(data_properties[:references]).to eq({ type: 'array', items: { type: ['string', 'object'] } })
    end
  end

  describe '.call' do
    it 'checks rate limit' do
      described_class.call(type: 'exploit', name: 'windows/smb/ms17_010_eternalblue', server_context: server_context)
      expect(rate_limiter).to have_received(:check_rate_limit!).with('module_info')
    end

    it 'calls Metasploit client with module type and name' do
      described_class.call(type: 'exploit', name: 'windows/smb/ms17_010_eternalblue', server_context: server_context)
      expect(msf_client).to have_received(:module_info).with('exploit', 'windows/smb/ms17_010_eternalblue')
    end

    it 'returns MCP::Tool::Response' do
      result = described_class.call(type: 'exploit', name: 'windows/smb/ms17_010_eternalblue', server_context: server_context)
      expect(result).to be_a(MCP::Tool::Response)
    end

    it 'includes metadata in response' do
      result = described_class.call(type: 'exploit', name: 'windows/smb/ms17_010_eternalblue', server_context: server_context)

      metadata = result.structured_content[:metadata]
      expect(metadata[:query_time]).to be_a(Float)
    end

    it 'includes transformed data in response' do
      result = described_class.call(type: 'exploit', name: 'windows/smb/ms17_010_eternalblue', server_context: server_context)

      data = result.structured_content[:data]
      expect(data).to be_a(Hash)
      expect(data[:fullname]).to eq('exploit/windows/smb/ms17_010_eternalblue')
      expect(data[:type]).to eq('exploit')
    end

    it 'validates module type' do
      expect {
        described_class.call(type: 'invalid', name: 'test', server_context: server_context)
      }.to raise_error(MsfMcp::MCP::ValidationError)
    end

    it 'validates module name' do
      expect {
        described_class.call(type: 'exploit', name: '', server_context: server_context)
      }.to raise_error(MsfMcp::MCP::ValidationError)
    end

    it 'converts authentication errors to MCP ToolExecutionError' do
      allow(msf_client).to receive(:module_info).and_raise(
        MsfMcp::Metasploit::AuthenticationError.new('Invalid token')
      )

      expect {
        described_class.call(type: 'exploit', name: 'test', server_context: server_context)
      }.to raise_error(MsfMcp::MCP::ToolExecutionError, /Authentication failed/)
    end

    it 'converts API errors to MCP ToolExecutionError' do
      allow(msf_client).to receive(:module_info).and_raise(
        MsfMcp::Metasploit::APIError.new('Server error')
      )

      expect {
        described_class.call(type: 'exploit', name: 'test', server_context: server_context)
      }.to raise_error(MsfMcp::MCP::ToolExecutionError, /Metasploit API error/)
    end
  end
end
