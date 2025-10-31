"""
Interactive setup wizard for AutoPurple
"""
import os
import sys
import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

console = Console()

def setup_command():
    """Interactive setup wizard for AutoPurple."""
    console.print(Panel.fit("🟣 AutoPurple Setup Wizard", style="bold blue"))
    
    # Check if already configured
    config_file = Path.home() / ".autopurple" / "config.yaml"
    if config_file.exists():
        if not Confirm.ask("AutoPurple is already configured. Reconfigure?"):
            return
    
    # Create config directory
    config_dir = Path.home() / ".autopurple"
    config_dir.mkdir(exist_ok=True)
    
    console.print("\n🔧 [bold]Setting up AutoPurple components...[/bold]")
    
    # Step 1: Install UV if not present
    setup_uv()
    
    # Step 2: Install MCP servers
    setup_mcp_servers()
    
    # Step 3: Configure Claude API
    claude_key = setup_claude_api()
    
    # Step 4: Configure AWS
    setup_aws()
    
    # Step 5: Create config file
    create_config_file(config_dir / "config.yaml", claude_key)
    
    # Step 6: Test the setup
    test_setup()
    
    console.print("\n🎉 [bold green]AutoPurple setup complete![/bold green]")
    console.print("You can now run: [bold cyan]autopurple run --region us-east-1[/bold cyan]")

def setup_uv():
    """Install UV package manager if not present."""
    console.print("\n📦 [bold]Installing UV package manager...[/bold]")
    
    # Check if uv is installed
    try:
        subprocess.run(["uvx", "--version"], check=True, capture_output=True)
        console.print("✅ UV is already installed")
        return
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    try:
        # Install UV
        console.print("Installing UV...")
        subprocess.run([sys.executable, "-m", "pip", "install", "uv"], check=True)
        console.print("✅ UV installed successfully")
    except subprocess.CalledProcessError as e:
        console.print(f"❌ Failed to install UV: {e}")
        raise typer.Exit(1)

def setup_mcp_servers():
    """Install and configure MCP servers."""
    console.print("\n🔧 [bold]Installing MCP servers...[/bold]")
    
    servers = [
        ("awslabs.ccapi-mcp-server", "AWS CCAPI MCP Server"),
        ("awslabs.aws-documentation-mcp-server", "AWS Documentation MCP Server")
    ]
    
    for server_package, description in servers:
        try:
            console.print(f"Installing {description}...")
            
            # Install using uvx
            result = subprocess.run(
                ["uvx", "install", server_package], 
                check=True, 
                capture_output=True,
                text=True
            )
            console.print(f"✅ {description} installed successfully")
            
        except subprocess.CalledProcessError as e:
            console.print(f"❌ Failed to install {description}: {e.stderr}")
            console.print("⚠️  MCP servers may not work properly")

def setup_claude_api():
    """Configure Claude API key."""
    console.print("\n🧠 [bold]Configuring Claude AI...[/bold]")
    
    # Check if key already exists in environment
    existing_key = os.environ.get('CLAUDE_API_KEY')
    if existing_key and existing_key.startswith('sk-ant-api'):
        console.print("✅ Claude API key found in environment")
        return existing_key
    
    console.print("To use Claude AI analysis, you need an API key from Anthropic.")
    console.print("Get one at: [link]https://console.anthropic.com/[/link]")
    
    while True:
        claude_key = Prompt.ask(
            "Enter your Claude API key (starts with sk-ant-api...)", 
            password=True
        )
        
        if not claude_key:
            if Confirm.ask("Skip Claude configuration? (Analysis will use fallback mode)"):
                return None
            continue
            
        if not claude_key.startswith('sk-ant-api'):
            console.print("❌ Invalid Claude API key format. It should start with 'sk-ant-api'")
            continue
            
        # Test the API key
        if test_claude_key(claude_key):
            console.print("✅ Claude API key validated successfully")
            return claude_key
        else:
            console.print("❌ Claude API key validation failed")
            if not Confirm.ask("Try again?"):
                return None

def test_claude_key(api_key: str) -> bool:
    """Test if Claude API key works."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        
        # Make a simple test call
        response = client.messages.create(
            model="claude-3-5-haiku-20241022",
            max_tokens=10,
            messages=[{"role": "user", "content": "Hello"}]
        )
        return True
    except Exception:
        return False

def setup_aws():
    """Configure AWS credentials."""
    console.print("\n☁️  [bold]Configuring AWS credentials...[/bold]")
    
    # Check if AWS credentials exist
    aws_profile = os.environ.get('AWS_PROFILE', 'default')
    aws_region = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
    
    if os.environ.get('AWS_ACCESS_KEY_ID') or os.path.exists(Path.home() / '.aws' / 'credentials'):
        console.print("✅ AWS credentials found")
        return
    
    console.print("AWS credentials not found. Please configure them:")
    console.print("1. Set environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
    console.print("2. Use AWS CLI: [bold cyan]aws configure[/bold cyan]")
    console.print("3. Use IAM roles (for EC2/ECS/Lambda)")
    
    if not Confirm.ask("Continue without configuring AWS now?"):
        raise typer.Exit(1)

def create_config_file(config_path: Path, claude_key: Optional[str]):
    """Create AutoPurple configuration file."""
    console.print(f"\n📝 [bold]Creating configuration file at {config_path}...[/bold]")
    
    config_content = f"""
# AutoPurple Configuration
version: "1.0"

# Claude AI Configuration
claude:
  api_key: "{claude_key or 'your-claude-api-key-here'}"
  model: "claude-3-5-haiku-20241022"
  max_tokens: 4000

# AWS Configuration
aws:
  profile: "default"
  region: "us-east-1"

# MCP Server Configuration
mcp:
  ccapi:
    command: ["uvx", "run", "awslabs.ccapi-mcp-server@latest", "--stdio"]
    enabled: true
  docs:
    command: ["uvx", "run", "awslabs.aws-documentation-mcp-server@latest", "--stdio"] 
    enabled: true

# Pipeline Configuration
pipeline:
  max_concurrent_findings: 10
  max_concurrent_validations: 5
  max_concurrent_remediations: 3
  dry_run_default: true

# Logging
logging:
  level: "INFO"
  format: "json"

# Timeouts (seconds)
timeouts:
  scoutsuite: 3600
  pacu: 1800
  mcp: 300
"""
    
    config_path.write_text(config_content.strip())
    console.print("✅ Configuration file created")

def test_setup():
    """Test the AutoPurple setup."""
    console.print("\n🧪 [bold]Testing AutoPurple setup...[/bold]")
    
    try:
        # Test health check
        result = subprocess.run(
            [sys.executable, "-m", "autopurple.cli.main", "health"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            console.print("✅ Health check passed")
        else:
            console.print(f"⚠️  Health check issues: {result.stdout}")
            
    except subprocess.TimeoutExpired:
        console.print("⚠️  Health check timed out")
    except Exception as e:
        console.print(f"⚠️  Health check error: {e}")

if __name__ == "__main__":
    setup_command()
