"""
Integration between Claude API and MCP servers.

This module allows Claude to directly use MCP server tools by:
1. Listing tools from MCP servers
2. Converting MCP tool schemas to Anthropic API tool format
3. Passing tools to Claude API
4. Executing Claude's tool use requests via MCP servers
"""

import json
from typing import Any, Dict, List, Optional

from ..adapters.mcp.stdio_client import AWSCCAPIMCPClient, AWSDocsMCPClient
from ..logging import get_logger

logger = get_logger(__name__)


class MCPClaudeIntegration:
    """Integrates MCP servers with Claude API by exposing tools."""
    
    def __init__(
        self,
        ccapi_client: Optional[AWSCCAPIMCPClient] = None,
        docs_client: Optional[AWSDocsMCPClient] = None
    ):
        """Initialize MCP-Claude integration."""
        self.ccapi_client = ccapi_client
        self.docs_client = docs_client
        self._mcp_tools_cache: Optional[List[Dict[str, Any]]] = None
    
    async def get_claude_tools(self) -> List[Dict[str, Any]]:
        """
        Get MCP server tools converted to Anthropic API tool format.
        
        Returns list of tool definitions that can be passed to Claude API.
        """
        if self._mcp_tools_cache:
            return self._mcp_tools_cache
        
        tools = []
        
        # Get tools from CCAPI MCP server (start it first if needed)
        if self.ccapi_client:
            try:
                # Start server if not already started
                if not self.ccapi_client.process:
                    await self.ccapi_client.start()
                    logger.info("Started CCAPI MCP server to get tools")
                
                ccapi_tools = await self.ccapi_client.list_tools()
                for mcp_tool in ccapi_tools.get('tools', []):
                    claude_tool = self._convert_mcp_tool_to_claude(mcp_tool, prefix='ccapi_')
                    if claude_tool:
                        tools.append(claude_tool)
                logger.info(f"Exposed {len([t for t in tools if t.get('name', '').startswith('ccapi_')])} CCAPI tools to Claude")
            except Exception as e:
                logger.warning(f"Failed to get CCAPI tools: {e}")
        
        # Get tools from Docs MCP server (start it first if needed)
        if self.docs_client:
            try:
                # Start server if not already started
                if not self.docs_client.process:
                    await self.docs_client.start()
                    logger.info("Started Docs MCP server to get tools")
                
                docs_tools = await self.docs_client.list_tools()
                for mcp_tool in docs_tools.get('tools', []):
                    claude_tool = self._convert_mcp_tool_to_claude(mcp_tool, prefix='docs_')
                    if claude_tool:
                        tools.append(claude_tool)
                logger.info(f"Exposed {len([t for t in tools if t.get('name', '').startswith('docs_')])} Docs tools to Claude")
            except Exception as e:
                logger.warning(f"Failed to get Docs tools: {e}")
        
        self._mcp_tools_cache = tools
        return tools
    
    def _convert_mcp_tool_to_claude(
        self,
        mcp_tool: Dict[str, Any],
        prefix: str = ""
    ) -> Optional[Dict[str, Any]]:
        """
        Convert MCP tool schema to Anthropic API tool format.
        
        MCP tools have:
        - name: tool name
        - description: tool description
        - inputSchema: JSON schema for parameters
        
        Anthropic API tools need:
        - name: tool name
        - description: tool description
        - input_schema: JSON schema (same format)
        """
        try:
            tool_name = prefix + mcp_tool.get('name', '')
            if not tool_name:
                return None
            
            claude_tool = {
                "name": tool_name,
                "description": mcp_tool.get('description', 'AWS MCP tool'),
                "input_schema": mcp_tool.get('inputSchema', {
                    "type": "object",
                    "properties": {},
                    "required": []
                })
            }
            
            # Add any additional metadata
            if 'example' in mcp_tool:
                claude_tool['example'] = mcp_tool['example']
            
            return claude_tool
            
        except Exception as e:
            logger.warning(f"Failed to convert MCP tool to Claude format: {e}", tool=mcp_tool.get('name'))
            return None
    
    async def execute_claude_tool_use(
        self,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a tool use request from Claude via the appropriate MCP server.
        
        Args:
            tool_name: Tool name (may have prefix like 'ccapi_' or 'docs_')
            arguments: Arguments for the tool
        
        Returns:
            Result from MCP server
        """
        # Determine which MCP server to use based on prefix
        if tool_name.startswith('ccapi_'):
            actual_tool_name = tool_name[6:]  # Remove 'ccapi_' prefix
            if not self.ccapi_client:
                raise RuntimeError("CCAPI MCP client not available")
            
            # Ensure server is started
            if not self.ccapi_client.process:
                await self.ccapi_client.start()
            
            # For CCAPI tools that require credentials_token, add it if available
            # and not already present
            if actual_tool_name in ['generate_infrastructure_code', 'update_resource', 'create_resource']:
                if 'credentials_token' not in arguments and hasattr(self.ccapi_client, 'session_info'):
                    session_info = self.ccapi_client.session_info
                    if isinstance(session_info, dict):
                        cred_token = session_info.get('credentials_token')
                        if cred_token:
                            arguments['credentials_token'] = cred_token
                            logger.debug(f"Added credentials_token to {actual_tool_name} call")
            
            return await self.ccapi_client.call_tool(actual_tool_name, arguments)
        
        elif tool_name.startswith('docs_'):
            actual_tool_name = tool_name[5:]  # Remove 'docs_' prefix
            if not self.docs_client:
                raise RuntimeError("Docs MCP client not available")
            
            # Ensure server is started
            if not self.docs_client.process:
                await self.docs_client.start()
            
            return await self.docs_client.call_tool(actual_tool_name, arguments)
        
        else:
            # Try CCAPI first, then Docs
            if self.ccapi_client:
                try:
                    if not self.ccapi_client.process:
                        await self.ccapi_client.start()
                    return await self.ccapi_client.call_tool(tool_name, arguments)
                except RuntimeError:
                    pass
            
            if self.docs_client:
                if not self.docs_client.process:
                    await self.docs_client.start()
                return await self.docs_client.call_tool(tool_name, arguments)
            
            raise RuntimeError(f"No MCP client available for tool: {tool_name}")


