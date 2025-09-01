#!/usr/bin/env python3
"""Debug script for testing AWS MCP servers."""

import asyncio
import json
import logging
import sys

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_mcp_server(command: str, server_name: str):
    """Test an MCP server with basic communication."""
    logger.info(f"Testing {server_name} MCP server...")
    
    try:
        # Start the server process
        process = await asyncio.create_subprocess_exec(
            *command.split(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        logger.info(f"Started {server_name} process")
        
        # Send initialization message
        init_message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "clientInfo": {
                    "name": "AutoPurple-Debug",
                    "version": "0.1.0"
                }
            }
        }
        
        # Send message
        message_str = json.dumps(init_message) + "\n"
        process.stdin.write(message_str.encode())
        await process.stdin.drain()
        
        logger.info(f"Sent initialization to {server_name}")
        
        # Read response with timeout
        try:
            line = await asyncio.wait_for(process.stdout.readline(), timeout=10.0)
            if line:
                response = json.loads(line.decode().strip())
                logger.info(f"{server_name} initialization response: {response}")
                
                # From the response, we can see the capabilities
                capabilities = response.get("result", {}).get("capabilities", {})
                tools_supported = capabilities.get("tools", {})
                logger.info(f"{server_name} tools capability: {tools_supported}")
                
                # Try to call a specific tool based on the server type
                if "aws-documentation" in server_name.lower():
                    # Try search_documentation tool for docs server
                    test_tool_message = {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "search_documentation",
                            "arguments": {
                                "query": "S3 bucket policies"
                            }
                        }
                    }
                elif "ccapi" in server_name.lower():
                    # Try check_environment_variables for CCAPI
                    test_tool_message = {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "check_environment_variables",
                            "arguments": {}
                        }
                    }
                else:
                    test_tool_message = None
                
                if test_tool_message:
                    message_str = json.dumps(test_tool_message) + "\n"
                    process.stdin.write(message_str.encode())
                    await process.stdin.drain()
                    
                    # Read test tool response
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=10.0)
                    if line:
                        tool_response = json.loads(line.decode().strip())
                        logger.info(f"{server_name} test tool response: {tool_response}")
                
            else:
                logger.error(f"No response from {server_name}")
                
        except asyncio.TimeoutError:
            logger.error(f"Timeout waiting for {server_name} response")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON from {server_name}: {e}")
        
        # Clean up
        process.terminate()
        await process.wait()
        logger.info(f"Stopped {server_name}")
        
    except Exception as e:
        logger.error(f"Error testing {server_name}: {e}")

async def main():
    """Main debug function."""
    logger.info("Starting MCP server debug session...")
    
    # Test AWS Documentation MCP server
    await test_mcp_server("uvx awslabs.aws-documentation-mcp-server@latest", "AWS Docs")
    
    # Add a delay between tests
    await asyncio.sleep(2)
    
    # Test AWS CCAPI MCP server
    await test_mcp_server("uvx awslabs.ccapi-mcp-server@latest", "AWS CCAPI")
    
    logger.info("MCP debug session complete")

if __name__ == "__main__":
    asyncio.run(main())
