"""AWS Documentation MCP client for querying remediation guidance."""

import json
from typing import Any, Dict, List, Optional

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from ...config import get_settings
from ...logging import get_logger, log_mcp_call

logger = get_logger(__name__)


class DocsClient:
    """AWS Documentation MCP client for querying remediation guidance."""
    
    def __init__(self, endpoint: Optional[str] = None, *, timeout: float = 30):
        """Initialize the Docs client."""
        settings = get_settings()
        self._endpoint = endpoint or settings.mcp_endpoint_docs
        self._timeout = timeout
        
        if not self._endpoint:
            raise ValueError("Docs MCP endpoint not configured")
        
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
        """Make a call to the Docs MCP server."""
        url = f"{self._endpoint}/actions/{action}"
        params = {"dry_run": str(dry_run).lower()}
        
        # Log the call for audit purposes
        log_mcp_call(
            logger,
            server="docs",
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
                        "Docs call completed",
                        action=action,
                        dry_run=dry_run,
                        status_code=response.status,
                        result_keys=list(result.keys()) if isinstance(result, dict) else None
                    )
                    
                    return result
                    
        except aiohttp.ClientError as e:
            logger.error(
                "Docs call failed",
                action=action,
                dry_run=dry_run,
                error=str(e)
            )
            raise
    
    async def search_remediation_guidance(
        self,
        service: str,
        issue_type: str,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Search for remediation guidance for a specific service and issue."""
        payload = {
            "service": service,
            "issueType": issue_type
        }
        
        return await self.call("search_remediation_guidance", payload, dry_run=dry_run)
    
    async def get_service_limits(
        self,
        service: str,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Get service limits for a specific AWS service."""
        payload = {
            "service": service
        }
        
        return await self.call("get_service_limits", payload, dry_run=dry_run)
    
    async def get_best_practices(
        self,
        service: str,
        resource_type: str,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Get best practices for a specific service and resource type."""
        payload = {
            "service": service,
            "resourceType": resource_type
        }
        
        return await self.call("get_best_practices", payload, dry_run=dry_run)
    
    async def get_security_recommendations(
        self,
        service: str,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Get security recommendations for a specific service."""
        payload = {
            "service": service
        }
        
        return await self.call("get_security_recommendations", payload, dry_run=dry_run)
    
    async def search_documentation(
        self,
        query: str,
        services: Optional[List[str]] = None,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Search AWS documentation for specific content."""
        payload = {
            "query": query
        }
        
        if services:
            payload["services"] = services
        
        return await self.call("search_documentation", payload, dry_run=dry_run)
    
    async def get_api_reference(
        self,
        service: str,
        api_name: str,
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Get API reference documentation for a specific service and API."""
        payload = {
            "service": service,
            "apiName": api_name
        }
        
        return await self.call("get_api_reference", payload, dry_run=dry_run)
    
    async def get_example_code(
        self,
        service: str,
        operation: str,
        language: str = "python",
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Get example code for a specific service operation."""
        payload = {
            "service": service,
            "operation": operation,
            "language": language
        }
        
        return await self.call("get_example_code", payload, dry_run=dry_run)
    


    async def health_check(self) -> Dict[str, Any]:
        """Check if the Docs MCP server is healthy."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._endpoint}/health",
                    timeout=self._timeout
                ) as response:
                    response.raise_for_status()
                    return await response.json()
        except aiohttp.ClientError as e:
            logger.error("Docs health check failed", error=str(e))
            raise

