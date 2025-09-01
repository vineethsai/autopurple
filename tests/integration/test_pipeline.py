"""Integration tests for AutoPurple pipeline."""

import pytest
import asyncio
from datetime import datetime

from autopurple.models.runs import Run
from autopurple.orchestrator.pipeline import AutoPurplePipeline


class TestPipeline:
    """Integration tests for the AutoPurple pipeline."""
    
    @pytest.mark.asyncio
    async def test_pipeline_initialization(self):
        """Test that the pipeline can be initialized."""
        pipeline = AutoPurplePipeline()
        assert pipeline is not None
        assert pipeline.settings is not None
    
    @pytest.mark.asyncio
    async def test_pipeline_with_mock_run(self):
        """Test pipeline execution with a mock run."""
        # Create a mock run
        run = Run(
            id="test_run_1",
            started_at=datetime.utcnow(),
            aws_account="test-account",
            aws_region="us-east-1"
        )
        
        # Create pipeline
        pipeline = AutoPurplePipeline()
        
        # Note: This test would require mocking the external dependencies
        # (ScoutSuite, Pacu, MCP servers) to run successfully
        # For now, we just test that the pipeline can be created
        
        assert run.id == "test_run_1"
        assert run.status == "started"
        assert pipeline is not None

