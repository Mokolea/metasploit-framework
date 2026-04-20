# frozen_string_literal: true

require 'rex/logging/log_sink'

module Msf::MCP
  module Logging
    module Sinks
      # A Rex LogSink decorator that redacts credentials, tokens, and API keys
      # from log messages before delegating to a wrapped sink.
      #
      # @example Wrapping a flatfile sink
      #   inner = Rex::Logging::Sinks::Flatfile.new('msfmcp.log')
      #   sink  = Msf::MCP::Logging::Sinks::Sanitizing.new(inner)
      #   register_log_source('msfmcp', sink, 0)
      class Sanitizing
        include Rex::Logging::LogSink

        REDACTED = '[REDACTED]'

        SENSITIVE_PATTERNS = {
          password:     /password[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          token_keyval: /token[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          token_header: /token\s+[a-zA-Z0-9_\-\.]+/i,
          api_key:      /api[_-]?key[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          secret:       /secret[_-]?key[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          credential:   /credential[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          auth:         /auth[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          bearer:       /bearer\s+[a-zA-Z0-9_\-\.]+/i
        }.freeze

        # @param sink [Rex::Logging::LogSink] The underlying sink to write to
        def initialize(sink)
          @sink = sink
        end

        def log(sev, src, level, msg)
          @sink.log(sev, src, level, sanitize(msg))
        end

        def cleanup
          @sink.cleanup
        end

        private

        def sanitize(msg)
          return msg unless msg.is_a?(String)

          sanitized = msg.dup
          SENSITIVE_PATTERNS.each do |name, pattern|
            sanitized = sanitized.gsub(pattern) do |match|
              if name == :token_header || name == :bearer
                parts = match.split(/\s+/, 2)
                "#{parts[0]} #{REDACTED}"
              elsif match =~ /(.*[:=])\s*[\"']?/
                "#{Regexp.last_match[1]} #{REDACTED}"
              else
                REDACTED
              end
            end
          end
          sanitized
        end
      end
    end
  end
end
