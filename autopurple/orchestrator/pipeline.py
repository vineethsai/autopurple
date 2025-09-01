"""Main pipeline orchestrator for AutoPurple."""

import asyncio
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import anyio
from tenacity import retry, stop_after_attempt, wait_exponential

from ..adapters import ScoutSuiteAdapter, PacuAdapter
from ..adapters.mcp import CCAPIClient, CloudFormationClient, DocsClient
from ..config import get_settings
from ..db import DatabaseSession, init_database
from ..logging import get_logger, log_pipeline_event
from ..models.findings import Finding
from ..models.remediation import RemediationPlan
from ..models.runs import Run
from ..models.validations import ValidationResult
from ..orchestrator.planner import ClaudePlanner
from ..orchestrator.validators import PostRemediationValidator

logger = get_logger(__name__)


class AutoPurplePipeline:
    """Main pipeline orchestrator for AutoPurple."""
    
    def __init__(self):
        """Initialize the pipeline."""
        self.settings = get_settings()
        self.scoutsuite = ScoutSuiteAdapter()
        self.pacu = PacuAdapter()
        self.planner = ClaudePlanner()
        self.validator = PostRemediationValidator()
        
        # MCP clients
        self.ccapi_client = None
        self.cfn_client = None
        self.docs_client = None
        
        if self.settings.mcp_endpoint_ccapi:
            self.ccapi_client = CCAPIClient()
        if self.settings.mcp_endpoint_cfn:
            self.cfn_client = CloudFormationClient()
        if self.settings.mcp_endpoint_docs:
            self.docs_client = DocsClient()
    
    async def execute(
        self,
        run: Run,
        max_findings: int = 10,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Execute the complete AutoPurple pipeline."""
        start_time = time.time()
        
        try:
            # Initialize database
            await init_database()
            
            # Log pipeline start
            log_pipeline_event(
                logger,
                run_id=run.id,
                phase="started",
                aws_account=run.aws_account,
                aws_region=run.aws_region
            )
            
            # Phase 1: Discovery
            findings = await self._discover_findings(run)
            
            # Limit findings if specified
            if max_findings and len(findings) > max_findings:
                findings = findings[:max_findings]
                logger.info(f"Limited findings to {max_findings}")
            
            # Phase 2: Analysis
            analyzed_findings = await self._analyze_findings(findings, run)
            
            # Phase 3: Validation
            validated_findings = await self._validate_findings(analyzed_findings, run)
            
            # Phase 4: Planning
            remediation_plans = await self._plan_remediations(validated_findings, run)
            
            # Phase 5: Remediation
            remediated_findings = await self._remediate_findings(remediation_plans, run, dry_run)
            
            # Phase 6: Post-validation
            await self._post_validate_remediations(remediated_findings, run)
            
            # Complete the run
            duration = time.time() - start_time
            run.complete('remediated', f"Pipeline completed in {duration:.2f}s")
            
            # Log pipeline completion
            log_pipeline_event(
                logger,
                run_id=run.id,
                phase="completed",
                aws_account=run.aws_account,
                aws_region=run.aws_region,
                duration_ms=int(duration * 1000)
            )
            
            # Return results
            return self._build_results(run, findings, validated_findings, remediated_findings, duration)
            
        except Exception as e:
            # Mark run as failed
            run.fail(str(e))
            
            log_pipeline_event(
                logger,
                run_id=run.id,
                phase="failed",
                aws_account=run.aws_account,
                aws_region=run.aws_region,
                error=str(e)
            )
            
            logger.error("Pipeline execution failed", error=str(e))
            raise
    
    async def _discover_findings(self, run: Run) -> List[Finding]:
        """Phase 1: Discover findings using ScoutSuite."""
        log_pipeline_event(
            logger,
            run_id=run.id,
            phase="discovery",
            aws_account=run.aws_account,
            aws_region=run.aws_region
        )
        
        try:
            # Run ScoutSuite discovery
            # Only pass profile if not using environment variables
            aws_profile = None
            if not (os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY')):
                aws_profile = run.aws_account
            
            scoutsuite_data = await self.scoutsuite.run_discovery(
                aws_profile=aws_profile,
                aws_region=run.aws_region
            )
            
            # Normalize findings
            findings = self.scoutsuite.normalize_findings(scoutsuite_data, run.id)
            
            # Store findings in database
            async with DatabaseSession() as session:
                for finding in findings:
                    # Store finding in database
                    # This would be implemented with SQLAlchemy ORM
                    pass
            
            logger.info(f"Discovery completed: {len(findings)} findings found")
            return findings
            
        except Exception as e:
            logger.error("Discovery phase failed", error=str(e))
            raise
    
    async def _analyze_findings(self, findings: List[Finding], run: Run) -> List[Finding]:
        """Phase 2: Analyze findings using Claude."""
        log_pipeline_event(
            logger,
            run_id=run.id,
            phase="analysis",
            aws_account=run.aws_account,
            aws_region=run.aws_region
        )
        
        try:
            # Use Claude to analyze and prioritize findings
            analyzed_findings = await self.planner.analyze_findings(findings, run)
            
            logger.info(f"Analysis completed: {len(analyzed_findings)} findings analyzed")
            return analyzed_findings
            
        except Exception as e:
            logger.error("Analysis phase failed", error=str(e))
            raise
    
    async def _validate_findings(self, findings: List[Finding], run: Run) -> List[Finding]:
        """Phase 3: Validate findings using Pacu."""
        log_pipeline_event(
            logger,
            run_id=run.id,
            phase="validation",
            aws_account=run.aws_account,
            aws_region=run.aws_region
        )
        
        try:
            # Create Pacu session
            session_name = f"autopurple_{run.id}"
            await self.pacu.create_session(session_name)
            
            # Validate findings concurrently with limits
            semaphore = asyncio.Semaphore(self.settings.max_concurrent_validations)
            
            async def validate_finding(finding: Finding) -> Finding:
                async with semaphore:
                    validation = await self.pacu.validate_finding(finding, session_name)
                    
                    # Update finding status based on validation
                    if validation.is_exploitable:
                        finding.update_status('validated')
                    else:
                        finding.update_status('dismissed')
                    
                    # Store validation result
                    async with DatabaseSession() as db_session:
                        # Store validation in database
                        pass
                    
                    return finding
            
            # Run validations concurrently
            validated_findings = await asyncio.gather(
                *[validate_finding(finding) for finding in findings],
                return_exceptions=True
            )
            
            # Filter out exceptions and get successful validations
            successful_findings = []
            for result in validated_findings:
                if isinstance(result, Exception):
                    logger.error("Validation failed", error=str(result))
                else:
                    successful_findings.append(result)
            
            logger.info(f"Validation completed: {len(successful_findings)} findings validated")
            return successful_findings
            
        except Exception as e:
            logger.error("Validation phase failed", error=str(e))
            raise
    
    async def _plan_remediations(self, findings: List[Finding], run: Run) -> List[RemediationPlan]:
        """Phase 4: Plan remediations using Claude."""
        log_pipeline_event(
            logger,
            run_id=run.id,
            phase="planning",
            aws_account=run.aws_account,
            aws_region=run.aws_region
        )
        
        try:
            # Filter for exploitable findings
            exploitable_findings = [f for f in findings if f.status == 'validated']
            
            if not exploitable_findings:
                logger.info("No exploitable findings to remediate")
                return []
            
            # Get remediation guidance from docs
            remediation_plans = []
            
            for finding in exploitable_findings:
                # Skip docs client for now and use empty guidance
                guidance = {
                    "service": finding.service,
                    "title": finding.title,
                    "mock_guidance": "Use security best practices for this service"
                }
                
                # Plan remediation using Claude
                plan = await self.planner.plan_remediation(finding, guidance, run)
                remediation_plans.append(plan)
            
            logger.info(f"Planning completed: {len(remediation_plans)} remediation plans created")
            return remediation_plans
            
        except Exception as e:
            logger.error("Planning phase failed", error=str(e))
            raise
    
    async def _remediate_findings(
        self,
        remediation_plans: List[RemediationPlan],
        run: Run,
        dry_run: bool
    ) -> List[Finding]:
        """Phase 5: Execute remediations using MCP."""
        log_pipeline_event(
            logger,
            run_id=run.id,
            phase="remediation",
            aws_account=run.aws_account,
            aws_region=run.aws_region
        )
        
        try:
            if not remediation_plans:
                logger.info("No remediation plans to execute")
                return []
            
            # Execute remediations concurrently with limits
            semaphore = asyncio.Semaphore(self.settings.max_concurrent_remediations)
            
            async def execute_remediation(plan: RemediationPlan) -> Finding:
                async with semaphore:
                    try:
                        # Execute via MCP
                        if plan.mcp_server == 'ccapi' and self.ccapi_client:
                            result = await self.ccapi_client.call(
                                plan.mcp_call.get('action', ''),
                                plan.mcp_call.get('payload', {}),
                                dry_run=dry_run
                            )
                        elif plan.mcp_server == 'cfn' and self.cfn_client:
                            result = await self.cfn_client.call(
                                plan.mcp_call.get('action', ''),
                                plan.mcp_call.get('payload', {}),
                                dry_run=dry_run
                            )
                        else:
                            raise ValueError(f"Unsupported MCP server: {plan.mcp_server}")
                        
                        # Mark as executed
                        if not dry_run:
                            plan.execute(result.get('audit_ref', ''))
                        
                        # Update finding status
                        finding = await self._get_finding_by_id(plan.finding_id)
                        if finding:
                            finding.update_status('remediated')
                        
                        # Store remediation result
                        async with DatabaseSession() as db_session:
                            # Store remediation in database
                            pass
                        
                        return finding
                        
                    except Exception as e:
                        logger.error("Remediation failed", error=str(e), plan_id=plan.id)
                        plan.fail(str(e))
                        raise
            
            # Run remediations concurrently
            remediated_findings = await asyncio.gather(
                *[execute_remediation(plan) for plan in remediation_plans],
                return_exceptions=True
            )
            
            # Filter out exceptions and get successful remediations
            successful_findings = []
            for result in remediated_findings:
                if isinstance(result, Exception):
                    logger.error("Remediation failed", error=str(result))
                else:
                    successful_findings.append(result)
            
            logger.info(f"Remediation completed: {len(successful_findings)} findings remediated")
            return successful_findings
            
        except Exception as e:
            logger.error("Remediation phase failed", error=str(e))
            raise
    
    async def _post_validate_remediations(self, findings: List[Finding], run: Run) -> None:
        """Phase 6: Post-validate remediations."""
        log_pipeline_event(
            logger,
            run_id=run.id,
            phase="post_validation",
            aws_account=run.aws_account,
            aws_region=run.aws_region
        )
        
        try:
            # Re-run validation to confirm remediation
            for finding in findings:
                validation = await self.validator.validate_remediation(finding, run)
                
                if validation.is_exploitable:
                    logger.warning(f"Remediation may have failed for finding {finding.id}")
                else:
                    logger.info(f"Remediation confirmed for finding {finding.id}")
            
            logger.info("Post-validation completed")
            
        except Exception as e:
            logger.error("Post-validation phase failed", error=str(e))
            raise
    
    async def _get_finding_by_id(self, finding_id: str) -> Optional[Finding]:
        """Get a finding by ID from the database."""
        async with DatabaseSession() as session:
            # This would query the database
            # For now, return None
            return None
    
    def _build_results(
        self,
        run: Run,
        findings: List[Finding],
        validated_findings: List[Finding],
        remediated_findings: List[Finding],
        duration: float
    ) -> Dict[str, Any]:
        """Build results summary."""
        return {
            'run_id': run.id,
            'total_findings': len(findings),
            'validated': len([f for f in validated_findings if f.status == 'validated']),
            'exploitable': len([f for f in validated_findings if f.status == 'validated']),
            'remediated': len(remediated_findings),
            'duration': f"{duration:.2f}s",
            'findings': [f.to_dict() for f in findings],
            'status': run.status
        }

