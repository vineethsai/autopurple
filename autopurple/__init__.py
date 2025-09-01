"""AutoPurple - AI-driven AWS security automation system."""

__version__ = "0.1.0"
__author__ = "AutoPurple Team"

from .config import get_settings
from .logging import get_logger

__all__ = ["get_settings", "get_logger"]

