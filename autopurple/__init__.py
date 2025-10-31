"""
AutoPurple: Claude-powered AWS Security Automation

AutoPurple is an intelligent AWS security automation system that:
- Discovers vulnerabilities using ScoutSuite
- Analyzes findings with Claude AI for expert assessment  
- Validates exploitability using Pacu
- Remediates issues via AWS MCP servers

Usage:
    from autopurple import AutoPurplePipeline
    
    # Or use CLI:
    $ autopurple run --region us-east-1
"""

__version__ = "1.2.1"
__author__ = "AutoPurple Team"
__email__ = "team@autopurple.dev"

# Core functionality
from .config import get_settings
from .logging import get_logger

# Main pipeline class for programmatic use
from .orchestrator.pipeline import AutoPurplePipeline

__all__ = ["AutoPurplePipeline", "get_settings", "get_logger", "__version__"]

