"""
MCP Server Manager for AutoPurple
Handles automatic installation and management of MCP servers
"""
import subprocess
import sys
import os
import asyncio
from pathlib import Path
from typing import Dict, List, Optional
import json

from ...logging import get_logger

logger = get_logger(__name__)

class MCPServerManager:
    """Manages MCP server installation and lifecycle."""
    
    def __init__(self):
        self.servers = {
            "ccapi": {
                "package": "awslabs.ccapi-mcp-server@latest",
                "command": ["uvx", "awslabs.ccapi-mcp-server@latest", "--stdio"],
                "description": "AWS CCAPI MCP Server"
            },
            "docs": {
                "package": "awslabs.aws-documentation-mcp-server@latest", 
                "command": ["uvx", "awslabs.aws-documentation-mcp-server@latest", "--stdio"],
                "description": "AWS Documentation MCP Server"
            }
        }
        self.running_servers = {}
    
    async def ensure_servers_installed(self):
        """Preflight check for MCP servers (no install required with uvx)."""
        logger.info("Preflighting MCP servers...")
        await self._ensure_uv_installed()
        for server_id, server_info in self.servers.items():
            await self._ensure_server_installed(server_id, server_info)
    
    async def _ensure_uv_installed(self):
        """Ensure UV package manager is installed."""
        try:
            result = subprocess.run(["uvx", "--version"], capture_output=True)
            if result.returncode == 0:
                logger.info("UV package manager is available")
                return
        except FileNotFoundError:
            pass
        
        logger.info("Installing UV package manager...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "uv"], check=True)
            logger.info("UV package manager installed successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install UV: {e}")
            raise RuntimeError("Could not install UV package manager")
    
    async def _ensure_server_installed(self, server_id: str, server_info: Dict):
        """Verify an MCP server can be executed via uvx (no installation)."""
        package = server_info["package"]
        description = server_info["description"]
        
        logger.info(f"Checking {description}...")
        
        try:
            # Try to run the server with --help to check if it's installed
            result = subprocess.run(
                ["uvx", "run", package, "--help"],
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"✅ {description} is installed")
                return
                
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning(f"{description} preflight failed; will attempt to run on-demand")
    
    async def start_server(self, server_id: str) -> Optional[subprocess.Popen]:
        """Start a specific MCP server."""
        if server_id not in self.servers:
            logger.error(f"Unknown server: {server_id}")
            return None
        
        server_info = self.servers[server_id]
        command = server_info["command"]
        description = server_info["description"]
        
        try:
            logger.info(f"Starting {description}...")
            
            # Start the server process
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Give it a moment to start
            await asyncio.sleep(1)
            
            # Check if it's still running
            if process.poll() is None:
                self.running_servers[server_id] = process
                logger.info(f"✅ {description} started successfully")
                return process
            else:
                stderr = process.stderr.read() if process.stderr else ""
                logger.error(f"Failed to start {description}: {stderr}")
                return None
                
        except Exception as e:
            logger.error(f"Error starting {description}: {e}")
            return None
    
    async def stop_server(self, server_id: str):
        """Stop a specific MCP server."""
        if server_id in self.running_servers:
            process = self.running_servers[server_id]
            try:
                process.terminate()
                await asyncio.sleep(1)
                if process.poll() is None:
                    process.kill()
                del self.running_servers[server_id]
                logger.info(f"Stopped {self.servers[server_id]['description']}")
            except Exception as e:
                logger.error(f"Error stopping server {server_id}: {e}")
    
    async def stop_all_servers(self):
        """Stop all running MCP servers."""
        for server_id in list(self.running_servers.keys()):
            await self.stop_server(server_id)
    
    def get_server_status(self) -> Dict[str, bool]:
        """Get the status of all servers."""
        status = {}
        for server_id in self.servers:
            if server_id in self.running_servers:
                process = self.running_servers[server_id]
                status[server_id] = process.poll() is None
            else:
                status[server_id] = False
        return status
    
    async def health_check(self) -> Dict[str, bool]:
        """Perform health check on all servers."""
        await self.ensure_servers_installed()
        
        health = {}
        for server_id, server_info in self.servers.items():
            try:
                # Try to start and immediately stop to test availability
                process = await self.start_server(server_id)
                if process:
                    await self.stop_server(server_id)
                    health[server_id] = True
                else:
                    health[server_id] = False
            except Exception:
                health[server_id] = False
        
        return health

# Global instance
mcp_manager = MCPServerManager()
