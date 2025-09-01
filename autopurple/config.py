"""Configuration management for AutoPurple."""

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """AutoPurple configuration settings."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # Environment
    env: str = Field(default="dev", description="Environment: dev, prod")
    
    # AWS Configuration
    aws_profile: Optional[str] = Field(default=None, description="AWS profile name")
    aws_region: str = Field(default="us-east-1", description="AWS region")
    
    # MCP Server Endpoints
    mcp_endpoint_ccapi: Optional[str] = Field(
        default=None, 
        description="AWS CCAPI MCP server endpoint"
    )
    mcp_endpoint_cfn: Optional[str] = Field(
        default=None, 
        description="AWS CloudFormation MCP server endpoint"
    )
    mcp_endpoint_docs: Optional[str] = Field(
        default=None, 
        description="AWS Documentation MCP server endpoint"
    )
    
    # AI/Claude Configuration
    claude_api_key: Optional[str] = Field(
        default=None, 
        description="Claude API key (or OpenAI API key)"
    )
    openai_api_key: Optional[str] = Field(
        default=None, 
        description="OpenAI API key (alternative to Claude)"
    )
    
    # Database Configuration
    db_path: Path = Field(
        default=Path.home() / ".autopurple" / "db.sqlite",
        description="SQLite database path"
    )
    
    # Logging Configuration
    log_level: str = Field(default="INFO", description="Logging level")
    log_format: str = Field(
        default="json", 
        description="Log format: json, console"
    )
    
    # Pipeline Configuration
    max_concurrent_findings: int = Field(
        default=10, 
        description="Maximum concurrent findings to process"
    )
    max_concurrent_validations: int = Field(
        default=5, 
        description="Maximum concurrent Pacu validations"
    )
    max_concurrent_remediations: int = Field(
        default=3, 
        description="Maximum concurrent MCP remediations"
    )
    
    # Timeouts
    scoutsuite_timeout: int = Field(
        default=3600, 
        description="ScoutSuite execution timeout in seconds"
    )
    pacu_timeout: int = Field(
        default=1800, 
        description="Pacu validation timeout in seconds"
    )
    mcp_timeout: int = Field(
        default=300, 
        description="MCP call timeout in seconds"
    )
    
    # Security Settings
    require_mfa: bool = Field(
        default=True, 
        description="Require MFA for AWS operations"
    )
    dry_run_default: bool = Field(
        default=True, 
        description="Default to dry-run mode for safety"
    )
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Ensure database directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get the global settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Reset the global settings instance (for testing)."""
    global _settings
    _settings = None

