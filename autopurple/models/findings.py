"""Finding data models for AutoPurple."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Literal

from dataclasses_json import DataClassJsonMixin, config

# Type aliases for better type safety
Severity = Literal['low', 'medium', 'high', 'critical']
FindingSource = Literal['scoutsuite']
FindingStatus = Literal['new', 'validated', 'dismissed', 'remediated']


@dataclass(slots=True)
class Finding(DataClassJsonMixin):
    """A security finding from ScoutSuite or other sources."""
    
    id: str
    run_id: str
    source: FindingSource
    service: str
    resource_id: str
    title: str
    severity: Severity
    evidence: Dict[str, Any]
    status: FindingStatus = field(default='new')
    created_at: datetime = field(
        default_factory=datetime.utcnow,
        metadata=config(encoder=datetime.isoformat, decoder=datetime.fromisoformat)
    )
    updated_at: datetime = field(
        default_factory=datetime.utcnow,
        metadata=config(encoder=datetime.isoformat, decoder=datetime.fromisoformat)
    )
    
    def __post_init__(self) -> None:
        """Validate finding data after initialization."""
        if not self.id:
            raise ValueError("Finding ID cannot be empty")
        if not self.run_id:
            raise ValueError("Run ID cannot be empty")
        if not self.service:
            raise ValueError("Service cannot be empty")
        if not self.resource_id:
            raise ValueError("Resource ID cannot be empty")
        if not self.title:
            raise ValueError("Title cannot be empty")
        if not self.evidence:
            raise ValueError("Evidence cannot be empty")
    
    def update_status(self, new_status: FindingStatus) -> None:
        """Update the finding status and timestamp."""
        self.status = new_status
        self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for database storage."""
        return {
            'id': self.id,
            'run_id': self.run_id,
            'source': self.source,
            'service': self.service,
            'resource_id': self.resource_id,
            'title': self.title,
            'severity': self.severity,
            'evidence': self.evidence,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        """Create finding from dictionary."""
        # Handle datetime fields
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if isinstance(data.get('updated_at'), str):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        
        return cls(**data)
    
    @property
    def is_critical(self) -> bool:
        """Check if finding is critical severity."""
        return self.severity == 'critical'
    
    @property
    def is_high_or_critical(self) -> bool:
        """Check if finding is high or critical severity."""
        return self.severity in ('high', 'critical')
    
    @property
    def evidence_summary(self) -> str:
        """Get a summary of the evidence."""
        if isinstance(self.evidence, dict):
            keys = list(self.evidence.keys())
            return f"Evidence keys: {', '.join(keys[:3])}{'...' if len(keys) > 3 else ''}"
        return str(self.evidence)[:100] + "..." if len(str(self.evidence)) > 100 else str(self.evidence)

