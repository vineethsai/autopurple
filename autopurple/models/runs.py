"""Run data models for AutoPurple pipeline execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Optional

from dataclasses_json import DataClassJsonMixin, config

# Type aliases
RunStatus = Literal['started', 'validated', 'remediated', 'failed']


@dataclass(slots=True)
class Run(DataClassJsonMixin):
    """A pipeline execution run."""
    
    id: str
    started_at: datetime
    ended_at: Optional[datetime] = field(default=None)
    aws_account: Optional[str] = field(default=None)
    aws_region: Optional[str] = field(default=None)
    status: RunStatus = field(default='started')
    notes: Optional[str] = field(default=None)
    created_at: datetime = field(
        default_factory=datetime.utcnow,
        metadata=config(encoder=datetime.isoformat, decoder=datetime.fromisoformat)
    )
    updated_at: datetime = field(
        default_factory=datetime.utcnow,
        metadata=config(encoder=datetime.isoformat, decoder=datetime.fromisoformat)
    )
    
    def __post_init__(self) -> None:
        """Validate run data after initialization."""
        if not self.id:
            raise ValueError("Run ID cannot be empty")
        if not self.started_at:
            raise ValueError("Started at cannot be empty")
    
    def complete(self, status: RunStatus, notes: Optional[str] = None) -> None:
        """Mark the run as completed."""
        self.status = status
        self.ended_at = datetime.utcnow()
        if notes:
            self.notes = notes
        self.updated_at = datetime.utcnow()
    
    def fail(self, error_message: str) -> None:
        """Mark the run as failed."""
        self.complete('failed', f"Error: {error_message}")
    
    def to_dict(self) -> dict:
        """Convert run to dictionary for database storage."""
        return {
            'id': self.id,
            'started_at': self.started_at.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'aws_account': self.aws_account,
            'aws_region': self.aws_region,
            'status': self.status,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> Run:
        """Create run from dictionary."""
        # Handle datetime fields
        if isinstance(data.get('started_at'), str):
            data['started_at'] = datetime.fromisoformat(data['started_at'])
        if isinstance(data.get('ended_at'), str):
            data['ended_at'] = datetime.fromisoformat(data['ended_at'])
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if isinstance(data.get('updated_at'), str):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        
        return cls(**data)
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Get the duration of the run in seconds."""
        if self.ended_at:
            return (self.ended_at - self.started_at).total_seconds()
        return None
    
    @property
    def is_completed(self) -> bool:
        """Check if the run is completed."""
        return self.status in ('validated', 'remediated', 'failed')
    
    @property
    def is_successful(self) -> bool:
        """Check if the run was successful."""
        return self.status in ('validated', 'remediated')

