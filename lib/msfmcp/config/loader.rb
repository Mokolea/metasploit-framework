# frozen_string_literal: true

require 'yaml'

module MsfMcp
  module Config
    class Loader
      # Load configuration from YAML file with environment variable overrides
      #
      # @param file_path [String] Path to YAML configuration file
      # @return [Hash] Configuration hash with symbolized keys
      # @raise [ConfigurationError] If file not found or invalid YAML
      def self.load(file_path)
        unless File.exist?(file_path)
          raise ConfigurationError, "Configuration file not found: #{file_path}"
        end

        begin
          config = YAML.safe_load_file(file_path, symbolize_names: true)
        rescue Psych::SyntaxError => e
          raise ConfigurationError, "Invalid YAML syntax in #{file_path}: #{e.message}"
        end

        unless config.is_a?(Hash)
          raise ConfigurationError, "Configuration file must contain a YAML hash/dictionary"
        end

        apply_defaults(config)
        apply_env_overrides(config)
        config
      end

      # Load configuration from hash (for testing)
      #
      # @param config_hash [Hash] Configuration hash
      # @return [Hash] Configuration hash with defaults and env overrides
      def self.load_from_hash(config_hash)
        config = config_hash.dup
        apply_defaults(config)
        apply_env_overrides(config)
        config
      end


      private

      # Apply default values to configuration
      #
      # @param config [Hash] Configuration hash to modify in place
      def self.apply_defaults(config)
        # Ensure nested hashes exist
        config[:msf_api] ||= {}
        config[:mcp] ||= {}

        # Default MSF API type and host
        config[:msf_api][:type] ||= 'messagepack'
        config[:msf_api][:host] ||= 'localhost'

        # Default port is 8081 for JSON-RPC or 55553 for MessagePack (and anything else)
        config[:msf_api][:port] ||= (config[:msf_api][:type] == 'json-rpc') ? 8081 : 55553

        # Use SSL by default
        config[:msf_api][:ssl] = true if !config[:msf_api].key?(:ssl)

        # Auto-start RPC by default
        config[:msf_api][:auto_start_rpc] = true unless config[:msf_api].key?(:auto_start_rpc)

        # Default endpoint based on API type
        config[:msf_api][:endpoint] ||= case config[:msf_api][:type]
                                         when 'json-rpc'
                                           MsfMcp::Metasploit::JsonRpcClient::DEFAULT_ENDPOINT
                                         else
                                           MsfMcp::Metasploit::MessagePackClient::DEFAULT_ENDPOINT
                                         end

        # Default transport
        config[:mcp][:transport] ||= 'stdio'

        # Default MCP server network settings (for HTTP transport)
        if config[:mcp][:transport] == 'http'
          config[:mcp][:host] ||= 'localhost'
          config[:mcp][:port] ||= 3000
        end

        # Default rate limit
        config[:rate_limit] ||= {}
        config[:rate_limit][:enabled] = true unless config[:rate_limit].key?(:enabled)
        config[:rate_limit][:requests_per_minute] ||= 60
        config[:rate_limit][:burst_size] ||= 10

        # Default logging
        config[:logging] ||= {}
        config[:logging][:enabled] = false unless config[:logging].key?(:enabled)
        config[:logging][:level] ||= 'INFO'
        config[:logging][:log_file] ||= 'msfmcp.log'
      end

      # Apply environment variable overrides
      #
      # @param config [Hash] Configuration hash to modify in place
      def self.apply_env_overrides(config)
        # Ensure nested hashes exist
        config[:msf_api] ||= {}
        config[:mcp] ||= {}

        # MSF API overrides
        config[:msf_api][:type] = ENV['MSF_API_TYPE'] if ENV['MSF_API_TYPE']
        config[:msf_api][:host] = ENV['MSF_API_HOST'] if ENV['MSF_API_HOST']
        config[:msf_api][:port] = ENV['MSF_API_PORT'].to_i if ENV['MSF_API_PORT']
        config[:msf_api][:ssl] = parse_boolean(ENV['MSF_API_SSL']) if ENV['MSF_API_SSL'] && !ENV['MSF_API_SSL'].empty?
        config[:msf_api][:endpoint] = ENV['MSF_API_ENDPOINT'] if ENV['MSF_API_ENDPOINT']
        config[:msf_api][:user] = ENV['MSF_API_USER'] if ENV['MSF_API_USER']
        config[:msf_api][:password] = ENV['MSF_API_PASSWORD'] if ENV['MSF_API_PASSWORD']
        config[:msf_api][:token] = ENV['MSF_API_TOKEN'] if ENV['MSF_API_TOKEN']
        config[:msf_api][:auto_start_rpc] = parse_boolean(ENV['MSF_AUTO_START_RPC']) if ENV['MSF_AUTO_START_RPC']

        # MCP transport override
        config[:mcp][:transport] = ENV['MCP_TRANSPORT'] if ENV['MCP_TRANSPORT']

        # MCP server network overrides
        config[:mcp][:host] = ENV['MCP_HOST'] if ENV['MCP_HOST']
        config[:mcp][:port] = ENV['MCP_PORT'].to_i if ENV['MCP_PORT']
      end

      # Parse a string value into a boolean
      #
      # @param value [String] String to parse ('true', '1', 'yes' → true; anything else → false)
      # @return [Boolean]
      def self.parse_boolean(value)
        %w[true 1 yes].include?(value.to_s.downcase)
      end
    end
  end
end
