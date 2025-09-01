"""Validation data models for AutoPurple."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Literal

from dataclasses_json import DataClassJsonMixin, config

# Type aliases
ValidationTool = Literal['pacu']
ValidationStatus = Literal['exploitable', 'not_exploitable', 'error']


@dataclass(slots=True)
class ValidationResult(DataClassJsonMixin):
    """A validation result from Pacu or other tools."""
    
    id: str
    finding_id: str
    tool: ValidationTool
    module: str
    executed_at: datetime
    result: ValidationStatus
    evidence: Dict[str, Any]
    created_at: datetime = field(
        default_factory=datetime.utcnow,
        metadata=config(encoder=datetime.isoformat, decoder=datetime.fromisoformat)
    )
    
    def __post_init__(self) -> None:
        """Validate validation result data after initialization."""
        if not self.id:
            raise ValueError("Validation ID cannot be empty")
        if not self.finding_id:
            raise ValueError("Finding ID cannot be empty")
        if not self.tool:
            raise ValueError("Tool cannot be empty")
        if not self.module:
            raise ValueError("Module cannot be empty")
        if not self.executed_at:
            raise ValueError("Executed at cannot be empty")
        if not self.evidence:
            raise ValueError("Evidence cannot be empty")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary for database storage."""
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'tool': self.tool,
            'module': self.module,
            'executed_at': self.executed_at.isoformat(),
            'result': self.result,
            'evidence': self.evidence,
            'created_at': self.created_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ValidationResult:
        """Create validation result from dictionary."""
        # Handle datetime fields
        if isinstance(data.get('executed_at'), str):
            data['executed_at'] = datetime.fromisoformat(data['executed_at'])
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        
        return cls(**data)
    
    @property
    def is_exploitable(self) -> bool:
        """Check if the finding was validated as exploitable."""
        return self.result == 'exploitable'
    
    @property
    def is_error(self) -> bool:
        """Check if the validation encountered an error."""
        return self.result == 'error'
    
    @property
    def evidence_summary(self) -> str:
        """Get a summary of the validation evidence."""
        if isinstance(self.evidence, dict):
            keys = list(self.evidence.keys())
            return f"Evidence keys: {', '.join(keys[:3])}{'...' if len(keys) > 3 else ''}"
        return str(self.evidence)[:100] + "..." if len(str(self.evidence)) > 100 else str(self.evidence)

