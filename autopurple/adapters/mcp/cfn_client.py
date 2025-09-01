"""AWS CloudFormation MCP client for declarative changes."""

import json
from typing import Any, Dict, Optional

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from ...config import get_settings
from ...logging import get_logger, log_mcp_call

logger = get_logger(__name__)


class CloudFormationClient:
    """AWS CloudFormation MCP client for declarative changes."""
    
    def __init__(self, endpoint: Optional[str] = None, *, timeout: float = 60):
        """Initialize the CloudFormation client."""
        settings = get_settings()
        self._endpoint = endpoint or settings.mcp_endpoint_cfn
        self._timeout = timeout
        
        if not self._endpoint:
            raise ValueError("CloudFormation MCP endpoint not configured")
        
        # Remove trailing slash for consistency
        self._endpoint = self._endpoint.rstrip('/')
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        reraise=True
    )
    async def call(
        self, 
        action: str, 
        payload: Dict[str, Any], 
        *, 
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Make a call to the CloudFormation MCP server."""
        url = f"{self._endpoint}/actions/{action}"
        params = {"dry_run": str(dry_run).lower()}
        
        # Log the call for audit purposes
        log_mcp_call(
            logger,
            server="cfn",
            action=action,
            payload=payload,
            dry_run=dry_run
        )
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, 
                    json=payload, 
                    params=params, 
                    timeout=self._timeout
                ) as response:
                    response.raise_for_status()
                    result = await response.json()
                    
                    logger.info(
                        "CloudFormation call completed",
                        action=action,
                        dry_run=dry_run,
                        status_code=response.status,
                        result_keys=list(result.keys()) if isinstance(result, dict) else None
                    )
                    
                    return result
                    
        except aiohttp.ClientError as e:
            logger.error(
                "CloudFormation call failed",
                action=action,
                dry_run=dry_run,
                error=str(e)
            )
            raise
    
    async def create_stack(
        self,
        stack_name: str,
        template_body: str,
        parameters: Optional[Dict[str, str]] = None,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Create a CloudFormation stack."""
        payload = {
            "stackName": stack_name,
            "templateBody": template_body
        }
        
        if parameters:
            payload["parameters"] = parameters
        
        return await self.call("create_stack", payload, dry_run=dry_run)
    
    async def update_stack(
        self,
        stack_name: str,
        template_body: str,
        parameters: Optional[Dict[str, str]] = None,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Update a CloudFormation stack."""
        payload = {
            "stackName": stack_name,
            "templateBody": template_body
        }
        
        if parameters:
            payload["parameters"] = parameters
        
        return await self.call("update_stack", payload, dry_run=dry_run)
    
    async def delete_stack(
        self,
        stack_name: str,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Delete a CloudFormation stack."""
        payload = {
            "stackName": stack_name
        }
        
        return await self.call("delete_stack", payload, dry_run=dry_run)
    
    async def create_change_set(
        self,
        stack_name: str,
        change_set_name: str,
        template_body: str,
        parameters: Optional[Dict[str, str]] = None,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Create a CloudFormation change set."""
        payload = {
            "stackName": stack_name,
            "changeSetName": change_set_name,
            "templateBody": template_body
        }
        
        if parameters:
            payload["parameters"] = parameters
        
        return await self.call("create_change_set", payload, dry_run=dry_run)
    
    async def execute_change_set(
        self,
        stack_name: str,
        change_set_name: str,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Execute a CloudFormation change set."""
        payload = {
            "stackName": stack_name,
            "changeSetName": change_set_name
        }
        
        return await self.call("execute_change_set", payload, dry_run=dry_run)
    
    async def describe_stack_events(
        self,
        stack_name: str,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Describe CloudFormation stack events."""
        payload = {
            "stackName": stack_name
        }
        
        return await self.call("describe_stack_events", payload, dry_run=dry_run)
    
    async def validate_template(
        self,
        template_body: str,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Validate a CloudFormation template."""
        payload = {
            "templateBody": template_body
        }
        
        return await self.call("validate_template", payload, dry_run=dry_run)
    
    async def health_check(self) -> Dict[str, Any]:
        """Check if the CloudFormation MCP server is healthy."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._endpoint}/health",
                    timeout=self._timeout
                ) as response:
                    response.raise_for_status()
                    return await response.json()
        except aiohttp.ClientError as e:
            logger.error("CloudFormation health check failed", error=str(e))
            raise

