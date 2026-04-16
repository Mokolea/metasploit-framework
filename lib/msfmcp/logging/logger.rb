# frozen_string_literal: true

require 'json'
require 'time'

module MsfMcp
  module Logging
    # Opt-in file logger with basic sanitization of sensitive data.
    #
    # It writes JSON lines to a log file with automatic redaction of credentials, tokens, and API keys.
    #
    # @example
    #   logger = MsfMcp::Logging::Logger.new
    #   logger.log_error(exception: e, message: "Request failed", context: { tool: "search_modules" })
    class Logger
      SENSITIVE_PATTERNS = {
        password: /password[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
        token_keyval: /token[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
        token_header: /token\s+[a-zA-Z0-9_\-\.]+/i,
        api_key: /api[_-]?key[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
        secret: /secret[_-]?key[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
        credential: /credential[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
        auth: /auth[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
        bearer: /bearer\s+[a-zA-Z0-9_\-\.]+/i
      }.freeze

      REDACTED = '[REDACTED]'

      SENSITIVE_KEYS = /\A(password|token|secret|api_key|api_secret|credential|auth_token|bearer|access_token|private_key)\z/i

      LOG_LEVELS = {
        'DEBUG' => 0,
        'INFO' => 1,
        'WARN' => 2,
        'ERROR' => 4,
        'FATAL' => 5
      }.freeze

      attr_reader :log_file, :log_level

      # Initialize logger
      #
      # @param log_file [String] Path to log file (default: 'msfmcp.log')
      # @param log_level [String] Minimum log level to write (default: 'INFO')
      def initialize(log_file: 'msfmcp.log', log_level: 'INFO')
        @log_file = log_file
        @log_level = log_level.to_s.upcase
        @log_level_priority = LOG_LEVELS[@log_level] || LOG_LEVELS['INFO']
      end

      # Log an error event
      #
      # @param exception [Exception] The exception that occurred
      # @param message [String] Human-readable error message
      # @param context [Hash] Additional context (tool name, params, etc.)
      # @return [void]
      def log_error(exception:, message:, context: {})
        log(
          level: 'ERROR',
          message: message,
          context: context,
          exception: {
            class: exception.class.name,
            message: sanitize_string(exception.message),
            backtrace: sanitize_backtrace(exception.backtrace&.first(5) || [])
          }
        )
      end

      # Log a general message at any level
      #
      # @param level [String] Log level ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')
      # @param message [String] The message to log
      # @param context [Hash] Additional context (optional)
      # @param exception [Hash] The exception details (optional)
      # @return [void]
      def log(level:, message:, context: {}, exception: {})
        # Filter by log level
        level_str = level.to_s.upcase
        level_priority = LOG_LEVELS[level_str] || LOG_LEVELS['INFO']
        return if level_priority < @log_level_priority

        log_entry = {
          timestamp: Time.now.utc.iso8601,
          level: level_str,
          message: sanitize_string(message)
        }
        log_entry[:context] = sanitize_for_log(context) unless context.empty?
        log_entry[:exception] = exception unless exception.empty?

        write_log_line(log_entry)
      end

      # Sanitize data for logging by redacting sensitive information
      #
      # Recursively processes hashes and arrays, redacting:
      # - Passwords, tokens, API keys, secrets
      # - Credentials
      #
      # @param data [Object] Data to sanitize (Hash, Array, String, or other)
      # @return [Object] Sanitized copy of data
      def sanitize_for_log(data)
        case data
        when Hash
          data.each_with_object({}) do |(k, v), result|
            result[k] = if k.to_s.match?(SENSITIVE_KEYS)
                          v.is_a?(Hash) || v.is_a?(Array) ? sanitize_for_log(v) : REDACTED
                        else
                          sanitize_for_log(v)
                        end
          end
        when Array
          data.map { |item| sanitize_for_log(item) }
        when String
          sanitize_string(data)
        else
          data
        end
      end

      private

      # Sanitize a string by redacting sensitive patterns
      #
      # @param str [String] String to sanitize
      # @return [String] Sanitized string
      def sanitize_string(str)
        return str unless str.is_a?(String)

        sanitized = str.dup

        # Redact sensitive patterns - match entire pattern and replace value part
        SENSITIVE_PATTERNS.each do |name, pattern|
          sanitized = sanitized.gsub(pattern) do |match|
            # For header-style tokens (token abc123, bearer abc123), replace the value
            if name == :token_header || name == :bearer
              parts = match.split(/\s+/, 2)
              "#{parts[0]} #{REDACTED}"
            # For key-value style (token: abc123, password=abc123), replace after separator
            elsif match =~ /(.*[:=])\s*[\"']?/
              "#{Regexp.last_match[1]} #{REDACTED}"
            else
              REDACTED
            end
          end
        end

        sanitized
      end

      # Sanitize backtrace by redacting sensitive information
      #
      # @param backtrace [Array<String>] Backtrace lines
      # @return [Array<String>] Sanitized backtrace
      def sanitize_backtrace(backtrace)
        backtrace.map { |line| sanitize_string(line) }
      end

      # Write a log entry as JSON line to file
      #
      # @param entry [Hash] Log entry data
      # @return [void]
      def write_log_line(entry)
        File.open(@log_file, 'a') do |f|
          f.puts(JSON.generate(entry))
        end
      rescue StandardError => e
        # If logging fails, write to stderr but don't crash
        warn "Failed to write log: #{e.message}"
      end
    end
  end
end
