# frozen_string_literal: true

# Main entry point for MSF MCP Server
module Msf
  module MCP
    VERSION = '0.1.0'
  end
end

# Error classes (load first)
require_relative 'mcp/errors'

# Configuration Layer
require_relative 'mcp/config/loader'
require_relative 'mcp/config/validator'

# Security Layer
require_relative 'mcp/security/input_validator'
require_relative 'mcp/security/rate_limiter'

# Metasploit Client Layer
require_relative 'mcp/rpc_manager'
require_relative 'mcp/metasploit/messagepack_client'
require_relative 'mcp/metasploit/jsonrpc_client'
require_relative 'mcp/metasploit/client'
require_relative 'mcp/metasploit/response_transformer'

# Logging Layer
require_relative 'mcp/logging/logger'

# MCP SDK
require 'mcp'

# MCP Layer
require_relative 'mcp/tools/tool_helper'
require_relative 'mcp/tools/search_modules'
require_relative 'mcp/tools/module_info'
require_relative 'mcp/tools/host_info'
require_relative 'mcp/tools/service_info'
require_relative 'mcp/tools/vulnerability_info'
require_relative 'mcp/tools/note_info'
require_relative 'mcp/tools/credential_info'
require_relative 'mcp/tools/loot_info'
require_relative 'mcp/server'

# Application Layer
require_relative 'mcp/application'
