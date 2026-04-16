# frozen_string_literal: true

require 'msfmcp'

RSpec.describe MsfMcp::Config::Validator do
  describe '.validate!' do
    context 'with valid messagepack configuration' do
      let(:valid_config) do
        {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            port: 55553,
            user: 'msf',
            password: 'password'
          }
        }
      end

      it 'returns true for valid configuration' do
        expect(described_class.validate!(valid_config)).to be true
      end

      it 'does not raise error' do
        expect { described_class.validate!(valid_config) }.not_to raise_error
      end
    end

    context 'with valid json-rpc configuration' do
      let(:valid_config) do
        {
          msf_api: {
            type: 'json-rpc',
            host: 'localhost',
            port: 8081,
            token: 'secret_token_123'
          }
        }
      end

      it 'returns true for valid configuration' do
        expect(described_class.validate!(valid_config)).to be true
      end
    end

    context 'with missing optional fields' do
      it 'does not raise error for missing msf_api.type (has default)' do
        config = { msf_api: { host: 'localhost', user: 'msf', password: 'pass' } }

        expect {
          described_class.validate!(config)
        }.not_to raise_error
      end

      it 'does not raise error for missing msf_api.host (has default)' do
        config = { msf_api: { type: 'messagepack', user: 'msf', password: 'pass' } }

        expect {
          described_class.validate!(config)
        }.not_to raise_error
      end

      it 'raises ValidationError for empty msf_api.type' do
        config = {
          msf_api: {
            type: '',
            host: 'localhost',
            user: 'msf',
            password: 'pass'
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.type']).to eq("must be one of the valid API types: messagepack, json-rpc")
        end
      end

      it 'raises ValidationError for whitespace-only msf_api.host' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: '   ',
            user: 'msf',
            password: 'pass'
          }
        }

        # Whitespace host is not validated as "required", loader will apply default
        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.host']).to eq("must be a non-empty string")
        end
      end

      it 'does not raise error for missing type and host (have defaults)' do
        config = { msf_api: { user: 'msf', password: 'pass' } }

        expect {
          described_class.validate!(config)
        }.not_to raise_error
      end
    end

    context 'with invalid enum values' do
      it 'raises ValidationError for invalid msf_api.type' do
        config = {
          msf_api: {
            type: 'soap',
            host: 'localhost'
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.type']).to eq("must be one of the valid API types: messagepack, json-rpc")
        end
      end

      it 'raises ValidationError for invalid mcp_transport' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            password: 'password'
          },
          mcp: {
            transport: 'websocket'
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'mcp.transport']).to eq("must be one of the valid transport: stdio, http")
        end
      end

      it 'allows valid mcp_transport http' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            password: 'password'
          },
          mcp: {
            transport: 'http'
          }
        }

        expect(described_class.validate!(config)).to be true
      end

      it 'allows valid mcp_transport stdio' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            password: 'password'
          },
          mcp: {
            transport: 'stdio'
          }
        }

        expect(described_class.validate!(config)).to be true
      end
    end

    context 'with port validation' do
      it 'accepts port 8080' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            port: 8080,
            user: 'msf',
            password: 'password'
          }
        }

        expect(described_class.validate!(config)).to be true
      end

      it 'accepts port 1' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            port: 1,
            user: 'msf',
            password: 'password'
          }
        }

        expect(described_class.validate!(config)).to be true
      end

      it 'accepts port 65535' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            port: 65535,
            user: 'msf',
            password: 'password'
          }
        }

        expect(described_class.validate!(config)).to be true
      end

      it 'rejects port 0' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            port: 0,
            user: 'msf',
            password: 'password'
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.port']).to eq('must be between 1 and 65535')
        end
      end

      it 'rejects negative port' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            port: -1,
            user: 'msf',
            password: 'password'
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.port']).to eq('must be between 1 and 65535')
        end
      end

      it 'rejects port 65536' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            port: 65536,
            user: 'msf',
            password: 'password'
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.port']).to eq('must be between 1 and 65535')
        end
      end
    end

    context 'with auto_start_rpc validation' do
      it 'accepts auto_start_rpc set to true' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            password: 'password',
            auto_start_rpc: true
          }
        }

        expect(described_class.validate!(config)).to be true
      end

      it 'accepts auto_start_rpc set to false' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            password: 'password',
            auto_start_rpc: false
          }
        }

        expect(described_class.validate!(config)).to be true
      end

      it 'raises ValidationError for non-boolean auto_start_rpc' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            password: 'password',
            auto_start_rpc: 'yes'
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.auto_start_rpc']).to eq('must be boolean (true or false)')
        end
      end

      it 'raises ValidationError for integer auto_start_rpc' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            password: 'password',
            auto_start_rpc: 1
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.auto_start_rpc']).to eq('must be boolean (true or false)')
        end
      end

      it 'does not raise error when auto_start_rpc is not present' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            password: 'password'
          }
        }

        expect { described_class.validate!(config) }.not_to raise_error
      end
    end

    context 'with conditional messagepack authentication requirements' do
      it 'raises ValidationError for missing msf_api.user when auto-start cannot generate credentials' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            password: 'password',
            auto_start_rpc: false
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.user']).to eq('is required for MessagePack authentication. Use --user option or MSF_API_USER environment variable')
        end
      end

      it 'raises ValidationError for empty msf_api.user' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: '',
            password: 'password',
            auto_start_rpc: false
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.user']).to eq('is required for MessagePack authentication. Use --user option or MSF_API_USER environment variable')
        end
      end

      it 'raises ValidationError for missing msf_api.password when auto-start cannot generate credentials' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            auto_start_rpc: false
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.password']).to eq('is required for MessagePack authentication. Use --password option or MSF_API_PASSWORD environment variable')
        end
      end

      it 'raises ValidationError for whitespace-only msf_api.password' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            password: '   ',
            auto_start_rpc: false
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.password']).to eq('is required for MessagePack authentication. Use --password option or MSF_API_PASSWORD environment variable')
        end
      end

      it 'raises ValidationError for both missing user and password when auto-start is disabled' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            auto_start_rpc: false
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.user']).to eq('is required for MessagePack authentication. Use --user option or MSF_API_USER environment variable')
          expect(error.errors[:'msf_api.password']).to eq('is required for MessagePack authentication. Use --password option or MSF_API_PASSWORD environment variable')
        end
      end

      it 'raises ValidationError for both missing user and password on remote host' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: '192.0.2.1',
            auto_start_rpc: true
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.user']).to be_a(String)
          expect(error.errors[:'msf_api.password']).to be_a(String)
        end
      end

      it 'raises ValidationError for only user provided (partial credentials)' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            user: 'msf',
            auto_start_rpc: true
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.password']).to be_a(String)
        end
      end

      it 'raises ValidationError for only password provided (partial credentials)' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            password: 'pass',
            auto_start_rpc: true
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.user']).to be_a(String)
        end
      end
    end

    context 'with optional credentials when auto-start can generate them' do
      it 'allows missing credentials on localhost with auto_start_rpc enabled' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            auto_start_rpc: true
          }
        }

        expect(described_class.validate!(config)).to be true
      end

      it 'allows missing credentials on 127.0.0.1 with auto_start_rpc enabled' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: '127.0.0.1',
            auto_start_rpc: true
          }
        }

        expect(described_class.validate!(config)).to be true
      end

      it 'allows missing credentials on ::1 with auto_start_rpc enabled' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: '::1',
            auto_start_rpc: true
          }
        }

        expect(described_class.validate!(config)).to be true
      end

      it 'allows missing credentials when auto_start_rpc key is absent (defaults to true)' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost'
          }
        }

        expect(described_class.validate!(config)).to be true
      end

      it 'does not allow missing credentials on remote host even with auto_start_rpc true' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: '192.0.2.1',
            auto_start_rpc: true
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError)
      end

      it 'does not allow missing credentials when auto_start_rpc is false' do
        config = {
          msf_api: {
            type: 'messagepack',
            host: 'localhost',
            auto_start_rpc: false
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError)
      end
    end

    context 'with conditional json-rpc authentication requirements' do
      it 'raises ValidationError for missing msf_api.token' do
        config = {
          msf_api: {
            type: 'json-rpc',
            host: 'localhost'
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.token']).to eq('is required for JSON-RPC authentication')
        end
      end

      it 'raises ValidationError for empty msf_api.token' do
        config = {
          msf_api: {
            type: 'json-rpc',
            host: 'localhost',
            token: ''
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.token']).to eq('is required for JSON-RPC authentication')
        end
      end

      it 'raises ValidationError for whitespace-only msf_api.token' do
        config = {
          msf_api: {
            type: 'json-rpc',
            host: 'localhost',
            token: '   '
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors[:'msf_api.token']).to eq('is required for JSON-RPC authentication')
        end
      end

      it 'accepts valid token' do
        config = {
          msf_api: {
            type: 'json-rpc',
            host: 'localhost',
            token: 'valid_token_123'
          }
        }

        expect(described_class.validate!(config)).to be true
      end
    end

    context 'with multiple validation errors' do
      it 'collects all validation errors' do
        config = {
          msf_api: {
            type: 'invalid_type',
            port: 0,
            user: 'msf',
            password: 'pass'
          },
          mcp: {
            transport: 'invalid'
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.errors.keys).to include(:'msf_api.type', :'msf_api.port', :'mcp.transport')
          expect(error.errors.size).to be >= 3
        end
      end

      it 'includes all errors in message' do
        config = {
          msf_api: {
            type: 'messagepack',
            port: 70000,
            user: '',
            password: ''
          }
        }

        expect {
          described_class.validate!(config)
        }.to raise_error(MsfMcp::Config::ValidationError) do |error|
          expect(error.message).to include('msf_api.port')
          expect(error.message).to include('msf_api.user')
          expect(error.message).to include('msf_api.password')
        end
      end
    end
  end

  describe '#credentials_can_be_generated?' do
    subject(:validator) { described_class.new }

    it 'returns true for localhost with auto_start_rpc true' do
      config = { msf_api: { host: 'localhost', auto_start_rpc: true } }
      expect(validator.send(:credentials_can_be_generated?, config)).to be true
    end

    it 'returns true for 127.0.0.1 with auto_start_rpc true' do
      config = { msf_api: { host: '127.0.0.1', auto_start_rpc: true } }
      expect(validator.send(:credentials_can_be_generated?, config)).to be true
    end

    it 'returns true for ::1 with auto_start_rpc true' do
      config = { msf_api: { host: '::1', auto_start_rpc: true } }
      expect(validator.send(:credentials_can_be_generated?, config)).to be true
    end

    it 'returns true when auto_start_rpc key is absent (not explicitly false)' do
      config = { msf_api: { host: 'localhost' } }
      expect(validator.send(:credentials_can_be_generated?, config)).to be true
    end

    it 'returns false when auto_start_rpc is false' do
      config = { msf_api: { host: 'localhost', auto_start_rpc: false } }
      expect(validator.send(:credentials_can_be_generated?, config)).to be false
    end

    it 'returns false for remote host' do
      config = { msf_api: { host: '192.0.2.1', auto_start_rpc: true } }
      expect(validator.send(:credentials_can_be_generated?, config)).to be false
    end

    it 'returns false for remote hostname' do
      config = { msf_api: { host: 'remote.example.com', auto_start_rpc: true } }
      expect(validator.send(:credentials_can_be_generated?, config)).to be false
    end

    it 'returns false when host is nil' do
      config = { msf_api: { auto_start_rpc: true } }
      expect(validator.send(:credentials_can_be_generated?, config)).to be false
    end
  end

  describe MsfMcp::Config::ValidationError do
    describe '#message' do
      it 'has default message for empty errors' do
        error = described_class.new({})
        expect(error.message).to eq('Configuration validation failed')
      end

      it 'includes field names and error descriptions' do
        errors = {
          :'msf_api.host' => 'is required',
          :'msf_api.port' => 'must be between 1 and 65535'
        }
        error = described_class.new(errors)

        expect(error.message).to include('msf_api.host is required')
        expect(error.message).to include('msf_api.port must be between 1 and 65535')
      end

      it 'formats multiple errors with bullets' do
        errors = {
          :'msf_api.type' => 'is required',
          :'msf_api.host' => 'is required'
        }
        error = described_class.new(errors)

        expect(error.message).to include('Configuration validation failed:')
        expect(error.message).to include('  - ')
      end
    end

    describe '#errors' do
      it 'provides access to errors hash' do
        errors = { :'msf_api.host' => 'is required' }
        error = described_class.new(errors)

        expect(error.errors).to eq(errors)
      end
    end
  end
end
