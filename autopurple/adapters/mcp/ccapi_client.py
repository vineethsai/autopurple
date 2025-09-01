"""AWS CCAPI MCP client for targeted resource changes."""

import json
from typing import Any, Dict, Optional

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from ...config import get_settings
from ...logging import get_logger, log_mcp_call

logger = get_logger(__name__)


class CCAPIClient:
    """AWS CCAPI MCP client for targeted resource changes."""
    
    def __init__(self, endpoint: Optional[str] = None, *, timeout: float = 30):
        """Initialize the CCAPI client."""
        settings = get_settings()
        self._endpoint = endpoint or settings.mcp_endpoint_ccapi
        self._timeout = timeout
        
        if not self._endpoint:
            raise ValueError("CCAPI MCP endpoint not configured")
        
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
        """Make a call to the CCAPI MCP server."""
        url = f"{self._endpoint}/actions/{action}"
        params = {"dry_run": str(dry_run).lower()}
        
        # Log the call for audit purposes
        log_mcp_call(
            logger,
            server="ccapi",
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
                        "CCAPI call completed",
                        action=action,
                        dry_run=dry_run,
                        status_code=response.status,
                        result_keys=list(result.keys()) if isinstance(result, dict) else None
                    )
                    
                    return result
                    
        except aiohttp.ClientError as e:
            logger.error(
                "CCAPI call failed",
                action=action,
                dry_run=dry_run,
                error=str(e)
            )
            raise
    
    async def update_iam_policy(
        self,
        policy_arn: str,
        new_policy_document: Dict[str, Any],
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Update an IAM policy."""
        payload = {
            "policyArn": policy_arn,
            "policyDocument": new_policy_document
        }
        
        return await self.call("update_iam_policy", payload, dry_run=dry_run)
    
    async def update_s3_bucket_policy(
        self,
        bucket_name: str,
        new_policy: Dict[str, Any],
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Update an S3 bucket policy."""
        payload = {
            "bucketName": bucket_name,
            "policy": new_policy
        }
        
        return await self.call("update_s3_bucket_policy", payload, dry_run=dry_run)
    
    async def update_security_group_rules(
        self,
        security_group_id: str,
        rules: Dict[str, Any],
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Update security group rules."""
        payload = {
            "securityGroupId": security_group_id,
            "rules": rules
        }
        
        return await self.call("update_security_group_rules", payload, dry_run=dry_run)
    
    async def update_kms_key_policy(
        self,
        key_id: str,
        new_policy: Dict[str, Any],
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Update a KMS key policy."""
        payload = {
            "keyId": key_id,
            "policy": new_policy
        }
        
        return await self.call("update_kms_key_policy", payload, dry_run=dry_run)
    
    async def update_lambda_function_configuration(
        self,
        function_name: str,
        configuration: Dict[str, Any],
        *,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Update Lambda function configuration."""
        payload = {
            "functionName": function_name,
            "configuration": configuration
        }
        
        return await self.call("update_lambda_function_configuration", payload, dry_run=dry_run)
    
    async def health_check(self) -> Dict[str, Any]:
        """Check if the CCAPI MCP server is healthy."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._endpoint}/health",
                    timeout=self._timeout
                ) as response:
                    response.raise_for_status()
                    return await response.json()
        except aiohttp.ClientError as e:
            logger.error("CCAPI health check failed", error=str(e))
            raise

