"""Structured logging configuration for AutoPurple."""

import sys
from typing import Any, Dict, Optional

import structlog
from structlog.types import Processor

from .config import get_settings


def setup_logging() -> None:
    """Configure structured logging for AutoPurple."""
    settings = get_settings()
    
    # Configure structlog
    processors: list[Processor] = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance."""
    return structlog.get_logger(name)


def log_audit_event(
    logger: structlog.stdlib.BoundLogger,
    event: str,
    actor: str,
    action: str,
    resource: str,
    status: str,
    duration_ms: Optional[int] = None,
    evidence_ref: Optional[str] = None,
    **kwargs: Any,
) -> None:
    """Log an audit event with standardized fields."""
    log_data: Dict[str, Any] = {
        "event": event,
        "actor": actor,
        "action": action,
        "resource": resource,
        "status": status,
    }
    
    if duration_ms is not None:
        log_data["duration_ms"] = duration_ms
    if evidence_ref is not None:
        log_data["evidence_ref"] = evidence_ref
    
    log_data.update(kwargs)
    
    logger.info(event, **log_data)


def log_pipeline_event(
    logger: structlog.stdlib.BoundLogger,
    run_id: str,
    phase: str,
    aws_account: Optional[str] = None,
    aws_region: Optional[str] = None,
    **kwargs: Any,
) -> None:
    """Log a pipeline event with run context."""
    log_data: Dict[str, Any] = {
        "run_id": run_id,
        "phase": phase,
    }
    
    if aws_account is not None:
        log_data["aws_account"] = aws_account
    if aws_region is not None:
        log_data["aws_region"] = aws_region
    
    log_data.update(kwargs)
    
    logger.info(f"pipeline.{phase}", **log_data)


def log_mcp_call(
    logger: structlog.stdlib.BoundLogger,
    server: str,
    action: str,
    payload: Dict[str, Any],
    dry_run: bool,
    **kwargs: Any,
) -> None:
    """Log an MCP server call."""
    log_data: Dict[str, Any] = {
        "mcp_server": server,
        "mcp_action": action,
        "dry_run": dry_run,
    }
    
    # Include payload summary but not full payload for security
    if payload:
        log_data["payload_keys"] = list(payload.keys())
        log_data["payload_size"] = len(str(payload))
    
    log_data.update(kwargs)
    
    logger.info("mcp.call", **log_data)


# Initialize logging on module import
setup_logging()

