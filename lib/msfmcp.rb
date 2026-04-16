# frozen_string_literal: true

# Main entry point for MSF MCP Server
module MsfMcp
  VERSION = '0.1.0'
end

# Error classes (load first)
require_relative 'msfmcp/errors'

# Configuration Layer
require_relative 'msfmcp/config/loader'
require_relative 'msfmcp/config/validator'

# Security Layer
require_relative 'msfmcp/security/input_validator'
require_relative 'msfmcp/security/rate_limiter'

# Metasploit Client Layer
require_relative 'msfmcp/rpc_manager'
require_relative 'msfmcp/metasploit/messagepack_client'
require_relative 'msfmcp/metasploit/jsonrpc_client'
require_relative 'msfmcp/metasploit/client'
require_relative 'msfmcp/metasploit/response_transformer'

# Logging Layer
require_relative 'msfmcp/logging/logger'

# MCP SDK
require 'mcp'

# MCP Layer
require_relative 'msfmcp/mcp/tools/search_modules'
require_relative 'msfmcp/mcp/tools/module_info'
require_relative 'msfmcp/mcp/tools/host_info'
require_relative 'msfmcp/mcp/tools/service_info'
require_relative 'msfmcp/mcp/tools/vulnerability_info'
require_relative 'msfmcp/mcp/tools/note_info'
require_relative 'msfmcp/mcp/tools/credential_info'
require_relative 'msfmcp/mcp/tools/loot_info'
require_relative 'msfmcp/mcp/server'

# Application Layer
require_relative 'msfmcp/application'
