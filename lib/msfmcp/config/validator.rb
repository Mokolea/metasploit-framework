# frozen_string_literal: true

module MsfMcp
  module Config
    class Validator
      VALID_API_TYPES = %w[messagepack json-rpc].freeze
      VALID_TRANSPORTS = %w[stdio http].freeze

      # Validate configuration hash (class method)
      #
      # @param config [Hash] Configuration hash to validate
      # @return [true] If validation passes
      # @raise [ValidationError] If validation fails
      def self.validate!(config)
        new.validate!(config)
      end

      # Validate configuration hash (instance method)
      #
      # @param config [Hash] Configuration hash to validate
      # @return [true] If validation passes
      # @raise [ValidationError] If validation fails
      def validate!(config)
        errors = {}

        # Check msf_api section exists
        unless config[:msf_api].is_a?(Hash)
          errors[:msf_api] = "configuration section is required"
          raise ValidationError.new(errors)
        end

        # Validate API type
        if config[:msf_api][:type] && !VALID_API_TYPES.include?(config[:msf_api][:type])
          errors[:'msf_api.type'] = "must be one of the valid API types: #{VALID_API_TYPES.join(', ')}"
        end

        # Validate API type
        if config[:msf_api][:host] && config[:msf_api][:host].to_s.strip.empty?
          errors[:'msf_api.host'] = "must be a non-empty string"
        end

        # Validate transport
        if config[:mcp] && config[:mcp][:transport] && !VALID_TRANSPORTS.include?(config[:mcp][:transport])
          errors[:'mcp.transport'] = "must be one of the valid transport: #{VALID_TRANSPORTS.join(', ')}"
        end

        # Validate port
        if config[:msf_api][:port]
          port = config[:msf_api][:port].to_i
          unless port.between?(1, 65535)
            errors[:'msf_api.port'] = "must be between 1 and 65535"
          end
        end

        # Validate SSL option
        if config[:msf_api].key?(:ssl) && ![true, false].include?(config[:msf_api][:ssl])
          errors[:'msf_api.ssl'] = "must be boolean (true or false)"
        end

        # Validate auto_start_rpc option
        if config[:msf_api].key?(:auto_start_rpc) && ![true, false].include?(config[:msf_api][:auto_start_rpc])
          errors[:'msf_api.auto_start_rpc'] = "must be boolean (true or false)"
        end

        # Validate MCP port
        if config[:mcp] && config[:mcp][:port]
          port = config[:mcp][:port].to_i
          unless port.between?(1, 65535)
            errors[:'mcp.port'] = "must be between 1 and 65535"
          end
        end

        # Validate conditional requirements based on API type
        if config[:msf_api][:type] == 'messagepack'
          validate_messagepack_auth(config, errors)
        elsif config[:msf_api][:type] == 'json-rpc'
          validate_jsonrpc_auth(config, errors)
        end

        # Raise error if any validation failed
        unless errors.empty?
          raise ValidationError.new(errors)
        end

        true
      end

      private

      LOCALHOST_HOSTS = %w[localhost 127.0.0.1 ::1].freeze

      # Validate MessagePack authentication fields
      #
      # Credentials are optional when auto-start can generate random ones
      # (auto_start_rpc enabled + localhost). If neither user nor password is
      # provided under those conditions, validation passes and the RPC manager
      # will generate random credentials at startup.
      def validate_messagepack_auth(config, errors)
        user_provided = config[:msf_api][:user] && !config[:msf_api][:user].to_s.strip.empty?
        password_provided = config[:msf_api][:password] && !config[:msf_api][:password].to_s.strip.empty?

        # Both provided — nothing to validate
        return if user_provided && password_provided

        # Neither provided and auto-start can generate them — OK
        return if !user_provided && !password_provided && credentials_can_be_generated?(config)

        # Otherwise, require both
        unless user_provided
          errors[:'msf_api.user'] = "is required for MessagePack authentication. Use --user option or MSF_API_USER environment variable"
        end

        unless password_provided
          errors[:'msf_api.password'] = "is required for MessagePack authentication. Use --password option or MSF_API_PASSWORD environment variable"
        end
      end

      # Whether the RPC manager can generate random credentials for this config.
      #
      # @param config [Hash] Configuration hash
      # @return [Boolean]
      def credentials_can_be_generated?(config)
        config[:msf_api][:auto_start_rpc] != false &&
          LOCALHOST_HOSTS.include?(config[:msf_api][:host].to_s.downcase)
      end

      # Validate JSON-RPC authentication fields
      def validate_jsonrpc_auth(config, errors)
        unless config[:msf_api][:token] && !config[:msf_api][:token].to_s.strip.empty?
          errors[:'msf_api.token'] = "is required for JSON-RPC authentication"
        end
      end
    end
  end
end
