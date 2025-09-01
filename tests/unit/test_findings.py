"""Unit tests for findings models."""

import pytest
from datetime import datetime

from autopurple.models.findings import Finding, Severity


class TestFinding:
    """Test cases for Finding model."""
    
    def test_finding_creation(self):
        """Test creating a finding with valid data."""
        finding = Finding(
            id="test_finding_1",
            run_id="test_run_1",
            source="scoutsuite",
            service="iam",
            resource_id="arn:aws:iam::123456789012:policy/test-policy",
            title="Overly permissive IAM policy",
            severity="high",
            evidence={"description": "Policy allows *:* actions"}
        )
        
        assert finding.id == "test_finding_1"
        assert finding.service == "iam"
        assert finding.severity == "high"
        assert finding.status == "new"
    
    def test_finding_validation(self):
        """Test finding validation with invalid data."""
        with pytest.raises(ValueError, match="Finding ID cannot be empty"):
            Finding(
                id="",
                run_id="test_run_1",
                source="scoutsuite",
                service="iam",
                resource_id="test-resource",
                title="Test finding",
                severity="medium",
                evidence={}
            )
    
    def test_finding_status_update(self):
        """Test updating finding status."""
        finding = Finding(
            id="test_finding_1",
            run_id="test_run_1",
            source="scoutsuite",
            service="iam",
            resource_id="test-resource",
            title="Test finding",
            severity="medium",
            evidence={}
        )
        
        original_updated_at = finding.updated_at
        finding.update_status("validated")
        
        assert finding.status == "validated"
        assert finding.updated_at > original_updated_at
    
    def test_finding_properties(self):
        """Test finding properties."""
        finding = Finding(
            id="test_finding_1",
            run_id="test_run_1",
            source="scoutsuite",
            service="iam",
            resource_id="test-resource",
            title="Test finding",
            severity="critical",
            evidence={"key1": "value1", "key2": "value2"}
        )
        
        assert finding.is_critical is True
        assert finding.is_high_or_critical is True
        assert "Evidence keys: key1, key2" in finding.evidence_summary
    
    def test_finding_serialization(self):
        """Test finding serialization to/from dict."""
        finding = Finding(
            id="test_finding_1",
            run_id="test_run_1",
            source="scoutsuite",
            service="iam",
            resource_id="test-resource",
            title="Test finding",
            severity="medium",
            evidence={"test": "data"}
        )
        
        # Test to_dict
        finding_dict = finding.to_dict()
        assert finding_dict["id"] == "test_finding_1"
        assert finding_dict["service"] == "iam"
        assert finding_dict["status"] == "new"
        
        # Test from_dict
        restored_finding = Finding.from_dict(finding_dict)
        assert restored_finding.id == finding.id
        assert restored_finding.service == finding.service
        assert restored_finding.evidence == finding.evidence

