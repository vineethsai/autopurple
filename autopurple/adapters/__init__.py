"""Adapters for external systems integration."""

from .scoutsuite_adapter import ScoutSuiteAdapter
from .pacu_adapter import PacuAdapter

# MCP HTTP clients are optional (require aiohttp) - use stdio clients instead
# They're available from .mcp package if needed

__all__ = [
    "ScoutSuiteAdapter",
    "PacuAdapter",
]

