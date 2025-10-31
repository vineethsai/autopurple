"""MCP (Model Context Protocol) client adapters."""

# Export stdio-based clients (primary)
from .stdio_client import AWSCCAPIMCPClient, AWSDocsMCPClient

# Also export HTTP-based clients for backward compatibility (optional - may fail if aiohttp not installed)
try:
    from .ccapi_client import CCAPIClient
    from .cfn_client import CloudFormationClient
    from .docs_client import DocsClient
    HTTP_CLIENTS_AVAILABLE = True
except ImportError:
    # HTTP clients not available (aiohttp not installed)
    HTTP_CLIENTS_AVAILABLE = False
    CCAPIClient = None
    CloudFormationClient = None
    DocsClient = None

__all__ = [
    # Stdio clients (primary)
    "AWSCCAPIMCPClient", 
    "AWSDocsMCPClient",
]

# Only add HTTP clients to __all__ if available
if HTTP_CLIENTS_AVAILABLE:
    __all__.extend(["CCAPIClient", "CloudFormationClient", "DocsClient"])

