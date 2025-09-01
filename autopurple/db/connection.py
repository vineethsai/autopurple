"""Database connection and initialization for AutoPurple."""

import asyncio
from pathlib import Path
from typing import Optional

import aiosqlite
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from ..config import get_settings
from ..logging import get_logger

logger = get_logger(__name__)

# Global database engine and session factory
_engine: Optional[create_async_engine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


async def init_database() -> None:
    """Initialize the database connection and create tables."""
    global _engine, _session_factory
    
    settings = get_settings()
    
    # Create async SQLite engine
    database_url = f"sqlite+aiosqlite:///{settings.db_path}"
    
    _engine = create_async_engine(
        database_url,
        echo=False,  # Set to True for SQL debugging
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    
    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    
    # Create tables
    await _create_tables()
    
    logger.info("Database initialized", db_path=str(settings.db_path))


async def _create_tables() -> None:
    """Create database tables from schema."""
    settings = get_settings()
    
    # Read schema file
    schema_path = Path(__file__).parent / "schema.sql"
    with open(schema_path, "r") as f:
        schema_sql = f.read()
    
    # Execute schema
    async with aiosqlite.connect(settings.db_path) as db:
        await db.executescript(schema_sql)
        await db.commit()
    
    logger.info("Database tables created")


async def get_database() -> AsyncSession:
    """Get a database session."""
    if _session_factory is None:
        await init_database()
    
    assert _session_factory is not None
    return _session_factory()


async def close_database() -> None:
    """Close database connections."""
    global _engine, _session_factory
    
    if _engine:
        await _engine.dispose()
        _engine = None
        _session_factory = None
    
    logger.info("Database connections closed")


# Context manager for database sessions
class DatabaseSession:
    """Context manager for database sessions."""
    
    def __init__(self):
        self.session: Optional[AsyncSession] = None
    
    async def __aenter__(self) -> AsyncSession:
        self.session = await get_database()
        return self.session
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

