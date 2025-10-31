"""Stdio-based MCP client for AWS MCP servers."""

import asyncio
import json
import uuid
from typing import Any, Dict, Optional

from ...config import get_settings
from ...logging import get_logger

logger = get_logger(__name__)


class StdioMCPClient:
    """MCP client that communicates via stdio with MCP servers."""
    
    def __init__(self, server_command: str):
        """Initialize the stdio MCP client."""
        self.server_command = server_command
        self.process: Optional[asyncio.subprocess.Process] = None
        self.message_id = 0
        self._read_lock = asyncio.Lock()  # Lock to prevent concurrent reads
        self._write_lock = asyncio.Lock()  # Lock to prevent concurrent writes
    
    async def start(self) -> None:
        """Start the MCP server process."""
        try:
            logger.info(f"Starting MCP server: {self.server_command}")
            
            # Split command properly - handle quoted arguments
            import shlex
            cmd_parts = shlex.split(self.server_command) if isinstance(self.server_command, str) else self.server_command
            
            # Start the server process
            self.process = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Send initialization message
            init_id = self._get_next_id()
            await self._send_message({
                "jsonrpc": "2.0",
                "id": init_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "clientInfo": {
                        "name": "AutoPurple",
                        "version": "0.1.0"
                    }
                }
            })
            
            # Wait a moment for server to start
            await asyncio.sleep(0.5)
            
            # Read initialization response with timeout
            try:
                response = await asyncio.wait_for(self._read_message(), timeout=10.0)
            except asyncio.TimeoutError:
                # Try to read stderr for debugging
                if self.process and self.process.stderr:
                    try:
                        stderr_data = await asyncio.wait_for(self.process.stderr.read(1024), timeout=1.0)
                        if stderr_data:
                            logger.error(f"MCP server stderr: {stderr_data.decode('utf-8', errors='ignore')}")
                    except Exception:
                        pass
                raise RuntimeError("MCP server initialization timeout - no response received")
            
            # Check if response matches our init request
            if response.get("id") == init_id:
                if "error" in response:
                    raise RuntimeError(f"MCP initialization error: {response['error']}")
                logger.info("MCP server initialized successfully")
            else:
                logger.warning("Received response with different ID", expected=init_id, received=response.get("id"))
                # Try to continue anyway - might be a notification
            
            # Send initialized notification (required by MCP protocol)
            await self._send_message({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            })
            
        except Exception as e:
            logger.error("Failed to start MCP server", error=str(e))
            if self.process:
                try:
                    await self.stop()
                except Exception:
                    pass
            raise
    
    async def stop(self) -> None:
        """Stop the MCP server process."""
        if self.process:
            try:
                self.process.terminate()
                await self.process.wait()
                logger.info("MCP server stopped")
            except Exception as e:
                logger.error("Error stopping MCP server", error=str(e))
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool on the MCP server."""
        if not self.process:
            raise RuntimeError("MCP server not started")
        
        try:
            # Send tool call message
            message = {
                "jsonrpc": "2.0",
                "id": self._get_next_id(),
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                }
            }
            
            await self._send_message(message)
            
            # Read response
            response = await self._read_message()
            
            # Check for errors
            if "error" in response:
                error_code = response["error"].get("code", -1)
                error_message = response["error"].get("message", "Unknown error")
                raise RuntimeError(f"MCP tool call error ({error_code}): {error_message}")
            
            # Return result
            result = response.get("result", {})
            
            # Handle MCP response format - content array
            if "content" in result:
                return result
            
            return result
            
        except Exception as e:
            logger.error("MCP tool call failed", tool=tool_name, error=str(e))
            raise
    
    async def list_tools(self) -> Dict[str, Any]:
        """List available tools on the MCP server."""
        if not self.process:
            raise RuntimeError("MCP server not started")
        
        try:
            message = {
                "jsonrpc": "2.0",
                "id": self._get_next_id(),
                "method": "tools/list",
                "params": {}
            }
            
            await self._send_message(message)
            response = await self._read_message()
            
            return response.get("result", {})
            
        except Exception as e:
            logger.error("Failed to list MCP tools", error=str(e))
            raise
    
    async def _send_message(self, message: Dict[str, Any]) -> None:
        """Send a message to the MCP server using newline-delimited JSON (NDJSON)."""
        if not self.process or not self.process.stdin:
            raise RuntimeError("Process not available")
        
        async with self._write_lock:
            try:
                # AWS MCP servers use newline-delimited JSON (one JSON object per line)
                body = json.dumps(message, ensure_ascii=False) + "\n"
                self.process.stdin.write(body.encode("utf-8"))
                await self.process.stdin.drain()
                
                logger.debug("Sent MCP message", message_id=message.get("id"), method=message.get("method"))
            except BrokenPipeError:
                raise RuntimeError("MCP server process terminated unexpectedly")
            except Exception as e:
                logger.error("Failed to send MCP message", error=str(e))
                raise
    
    async def _read_message(self) -> Dict[str, Any]:
        """Read a message from the MCP server using newline-delimited JSON (NDJSON)."""
        if not self.process or not self.process.stdout:
            raise RuntimeError("Process not available")
        
        # Use lock to prevent concurrent reads
        async with self._read_lock:
            # Check if process has terminated
            if self.process.returncode is not None:
                stderr_output = ""
                if self.process.stderr:
                    try:
                        stderr_data = await asyncio.wait_for(self.process.stderr.read(4096), timeout=1.0)
                        stderr_output = stderr_data.decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                raise RuntimeError(f"MCP server process terminated (exit code: {self.process.returncode}). Stderr: {stderr_output}")
            
            # AWS MCP servers use newline-delimited JSON (one JSON object per line)
            # Read one line (one JSON message)
            try:
                line = await asyncio.wait_for(self.process.stdout.readline(), timeout=10.0)
            except asyncio.TimeoutError:
                raise RuntimeError("Timeout waiting for MCP server response")
            
            if not line:
                if self.process.returncode is not None:
                    raise RuntimeError(f"MCP server process terminated (exit code: {self.process.returncode})")
                raise RuntimeError("No response from MCP server - EOF reached")
            
            # Parse the JSON line
            line_str = line.decode("utf-8").strip()
            if not line_str:
                # Empty line, try reading next line (recursive but locked)
                return await self._read_message()
            
            try:
                response = json.loads(line_str)
                logger.debug("Received MCP message", message_id=response.get("id"))
                return response
            except json.JSONDecodeError as e:
                logger.error("Invalid JSON response from MCP server", line=line_str, error=str(e))
                raise RuntimeError(f"Invalid JSON from MCP server: {e}")
    
    def _get_next_id(self) -> int:
        """Get the next message ID."""
        self.message_id += 1
        return self.message_id


class AWSDocsMCPClient(StdioMCPClient):
    """AWS Documentation MCP client."""
    
    def __init__(self):
        super().__init__("uvx awslabs.aws-documentation-mcp-server@latest")
    
    async def search_documentation(self, query: str, service: Optional[str] = None) -> Dict[str, Any]:
        """Search AWS documentation with fallback to alternative tool name."""
        arguments = {"query": query}
        if service:
            arguments["service"] = service
        
        try:
            return await self.call_tool("search_documentation", arguments)
        except RuntimeError as e:
            # Fallback to generic 'search' if parameters/tool name differ
            if "-32602" in str(e) or "Invalid request parameters" in str(e):
                return await self.call_tool("search", arguments)
            raise
    
    async def call(self, action: str, payload: Dict[str, Any], *, dry_run: bool = True) -> Dict[str, Any]:
        """Call method for compatibility with existing HTTP client interface."""
        return await self.call_tool(action, payload)


class AWSCCAPIMCPClient(StdioMCPClient):
    """AWS CCAPI MCP client following the mandatory workflow."""
    
    def __init__(self):
        super().__init__("uvx awslabs.ccapi-mcp-server@latest")
        self.session_info = None
        self.env_check_result = None
        self._server_ready = False
    
    async def start(self) -> None:
        """Start the MCP server and perform mandatory workflow."""
        try:
            await super().start()
            
            # Verify server is responsive
            await self._verify_server_health()
            
            # Execute mandatory CCAPI workflow
            await self._execute_ccapi_workflow()
            
            self._server_ready = True
            logger.info("CCAPI MCP server ready for operations")
            
        except Exception as e:
            logger.error("Failed to start CCAPI MCP server", error=str(e))
            await self.stop()
            raise
    
    async def _verify_server_health(self):
        """Verify server is responding correctly."""
        try:
            # List available tools
            tools = await self.list_tools()
            logger.info("Server health check passed", tool_count=len(tools.get('tools', [])))
        except Exception as e:
            raise RuntimeError(f"Server health check failed: {e}")
    
    async def _execute_ccapi_workflow(self):
        """Execute the mandatory CCAPI workflow."""
        # Preflight: list tools and try no-token account info to adapt to server
        try:
            tools_result = await self.list_tools()
            logger.info("CCAPI tools listed", tools=len(tools_result.get('tools', [])))
        except Exception:
            pass
        
        try:
            acct_result = await self.call_tool("get_aws_account_info", {})
            # Extract account info from MCP response format
            if isinstance(acct_result, dict) and 'content' in acct_result:
                import json
                for content_item in acct_result.get('content', []):
                    if isinstance(content_item, dict) and 'text' in content_item:
                        try:
                            acct_data = json.loads(content_item['text'])
                            account_id = acct_data.get('account_id', 'unknown')
                            logger.info("AWS account info", account=account_id)
                            # Store credentials token if present
                            if 'credentials_token' in acct_data:
                                self.session_info = {
                                    'credentials_token': acct_data['credentials_token']
                                }
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            logger.debug("Could not get account info", error=str(e))
            # Not fatal

        # Step 1: MANDATORY - check_environment_variables
        logger.info("Performing mandatory environment check")
        try:
            env_result = await self.call_tool("check_environment_variables", {})
            # Extract environment token from response
            if isinstance(env_result, dict) and 'content' in env_result:
                import json
                for content_item in env_result.get('content', []):
                    if isinstance(content_item, dict) and 'text' in content_item:
                        try:
                            env_data = json.loads(content_item['text'])
                            env_token = env_data.get('environment_token')
                            if env_token:
                                # Store for use in get_aws_session_info
                                if not self.session_info:
                                    self.session_info = {}
                                self.session_info['environment_token'] = env_token
                                logger.info("Environment token obtained")
                        except json.JSONDecodeError:
                            pass
            self.env_check_result = env_result
        except RuntimeError as e:
            # Retry with explicit empty requirements
            if "-32602" in str(e) or "Invalid request parameters" in str(e):
                self.env_check_result = await self.call_tool("check_environment_variables", {"required": []})
            else:
                raise
        
        # Step 2: MANDATORY - get_aws_session_info
        logger.info("Getting AWS session info")
        try:
            payload = {}
            # Get environment token from stored session_info or env_check_result
            if isinstance(self.session_info, dict) and 'environment_token' in self.session_info:
                payload["environment_token"] = self.session_info['environment_token']
            elif isinstance(self.env_check_result, dict):
                # Try to extract from env_check_result (could be in content format)
                env_token = self.env_check_result.get("environment_token")
                if not env_token and 'content' in self.env_check_result:
                    import json
                    for content_item in self.env_check_result.get('content', []):
                        if isinstance(content_item, dict) and 'text' in content_item:
                            try:
                                env_data = json.loads(content_item['text'])
                                env_token = env_data.get('environment_token')
                                if env_token:
                                    break
                            except json.JSONDecodeError:
                                pass
                if env_token:
                    payload["environment_token"] = env_token
                    if not self.session_info:
                        self.session_info = {}
                    self.session_info['environment_token'] = env_token
            
            from ...config import get_settings
            settings = get_settings()
            if getattr(settings, 'aws_region', None):
                payload["region"] = settings.aws_region
            
            session_result = await self.call_tool("get_aws_session_info", payload)
            
            # Store session info from response (extract from MCP content format if needed)
            if isinstance(session_result, dict) and 'content' in session_result:
                import json
                for content_item in session_result.get('content', []):
                    if isinstance(content_item, dict) and 'text' in content_item:
                        try:
                            session_data = json.loads(content_item['text'])
                            if not self.session_info:
                                self.session_info = {}
                            self.session_info.update(session_data)
                            logger.info("AWS session info obtained from MCP response")
                        except json.JSONDecodeError:
                            pass
            else:
                if not self.session_info:
                    self.session_info = {}
                if isinstance(session_result, dict):
                    self.session_info.update(session_result)
                else:
                    self.session_info = session_result
                logger.info("AWS session info obtained")
                
        except RuntimeError as e:
            if "-32602" in str(e) or "Invalid request parameters" in str(e) or "Field required" in str(e):
                logger.debug("get_aws_session_info failed, continuing without it", error=str(e))
                # Use existing session_info or env_check_result as fallback
                if not self.session_info:
                    self.session_info = self.env_check_result if isinstance(self.env_check_result, dict) else {}
            else:
                raise
        
        logger.info("CCAPI workflow initialization completed")
    
    async def call(self, action: str, payload: Dict[str, Any], *, dry_run: bool = True) -> Dict[str, Any]:
        """
        Call method for compatibility with existing HTTP client interface.
        
        NOTE: This is a generic wrapper around call_tool. For resource updates,
        Claude should use MCP tools directly (ccapi_update_resource) rather than
        calling through this method. This method is kept for backward compatibility.
        """
        if not self._server_ready:
            raise RuntimeError("CCAPI MCP server not ready. Call start() first.")
        
        if dry_run:
            logger.info("DRY RUN: Would execute MCP action", action=action, payload_keys=list(payload.keys()))
            return {"status": "dry_run", "action": action, "message": "Would have executed in real mode"}
        
        # Generic tool call - use call_tool directly
        # The payload should be the arguments for the MCP tool
        # No hardcoded methods needed - let Claude use MCP tools directly
        return await self.call_tool(action, payload)
