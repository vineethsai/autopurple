"""
Post-installation setup for AutoPurple
"""
import os
import sys
import subprocess
import platform
from pathlib import Path

def post_install():
    """Run post-installation setup for AutoPurple."""
    print("🟣 Setting up AutoPurple...")
    
    # Install UV if not present
    install_uv()
    
    # Install MCP servers
    install_mcp_servers()
    
    # Create config directory
    create_config_directory()
    
    print("✅ AutoPurple setup complete!")
    print("Run 'autopurple setup' for interactive configuration.")

def install_uv():
    """Install UV package manager."""
    try:
        subprocess.run(["uvx", "--version"], check=True, capture_output=True)
        print("✅ UV already installed")
        return
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    try:
        print("📦 Installing UV package manager...")
        subprocess.run([sys.executable, "-m", "pip", "install", "uv"], check=True)
        print("✅ UV installed")
    except subprocess.CalledProcessError:
        print("⚠️  Failed to install UV - MCP servers may not work")

def install_mcp_servers():
    """Pre-install MCP servers globally."""
    servers = [
        "awslabs.ccapi-mcp-server@latest",
        "awslabs.aws-documentation-mcp-server@latest"
    ]
    
    for server in servers:
        try:
            print(f"📡 Installing {server}...")
            subprocess.run(["uvx", "install", server], check=True, capture_output=True)
            print(f"✅ {server} installed")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"⚠️  Failed to install {server}")

def create_config_directory():
    """Create AutoPurple config directory."""
    config_dir = Path.home() / ".autopurple"
    config_dir.mkdir(exist_ok=True)
    print(f"📁 Config directory: {config_dir}")

if __name__ == "__main__":
    post_install()
