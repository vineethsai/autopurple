"""Main pipeline orchestrator for AutoPurple."""

import asyncio
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import anyio
from tenacity import retry, stop_after_attempt, wait_exponential

from ..adapters import ScoutSuiteAdapter, PacuAdapter
from ..config import get_settings
from ..db import DatabaseSession, init_database
from ..logging import get_logger, log_pipeline_event
from ..models.findings import Finding
from ..models.remediation import RemediationPlan
from ..models.runs import Run
from ..models.validations import ValidationResult
from ..orchestrator.planner import ClaudePlanner
from ..adapters.mcp.manager import mcp_manager
from ..orchestrator.validators import PostRemediationValidator

logger = get_logger(__name__)


class AutoPurplePipeline:
    """Main pipeline orchestrator for AutoPurple."""
    
    def __init__(self):
        """Initialize the pipeline."""
        self.settings = get_settings()
        # Require ScoutSuite and Pacu - no mock data
        self.scoutsuite = ScoutSuiteAdapter(allow_missing=False)
        self.pacu = PacuAdapter()
        self.planner = ClaudePlanner()
        self.validator = PostRemediationValidator()
        
        # MCP clients - using stdio instead of HTTP
        self.ccapi_client = None
        self.docs_client = None
        
        # Track findings during pipeline execution (for finding lookup)
        self._findings_cache: Dict[str, Finding] = {}
        
        # Import stdio clients and MCP-Claude integration
        try:
            from ..adapters.mcp.stdio_client import AWSCCAPIMCPClient, AWSDocsMCPClient
            from ..orchestrator.mcp_claude_integration import MCPClaudeIntegration
            
            self.ccapi_client = AWSCCAPIMCPClient()
            self.docs_client = AWSDocsMCPClient()
            
            # Create MCP-Claude integration so Claude can use MCP tools directly
            self.mcp_integration = MCPClaudeIntegration(
                ccapi_client=self.ccapi_client,
                docs_client=self.docs_client
            )
            
            # Pass integration to planner
            self.planner.mcp_integration = self.mcp_integration
            
            logger.info("Initialized MCP clients with Claude integration - Claude can now use MCP tools directly")
        except Exception as e:
            logger.warning("Failed to initialize MCP clients", error=str(e))
            self.mcp_integration = None
    
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
            
            # Cache findings for later lookup
            self._findings_cache = {f.id: f for f in findings}
            logger.info(f"Cached {len(self._findings_cache)} findings for lookup")
            
            # Limit findings if specified
            if max_findings and len(findings) > max_findings:
                findings = findings[:max_findings]
                logger.info(f"Limited findings to {max_findings}")
                # Update cache
                self._findings_cache = {f.id: f for f in findings}
            
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
            # Re-raise - don't use mock data
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
        
        # Pacu validation - try to use it, but continue if it fails
        if self.pacu is None:
            logger.warning("Pacu not available - marking all findings as validated for testing")
            for finding in findings:
                finding.update_status('validated')
            return findings
        
        try:
            # Create Pacu session
            session_name = f"autopurple_{run.id}"
            try:
                await self.pacu.create_session(session_name)
            except Exception as e:
                logger.warning(f"Pacu session creation failed: {e}. Marking findings as validated without Pacu validation.")
                for finding in findings:
                    finding.update_status('validated')
                return findings
            
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
            # Filter for exploitable findings - also include 'new' findings since validation may have been skipped
            # or findings may be marked as exploitable even if not validated yet
            exploitable_findings = [f for f in findings if f.status in ('validated', 'new')]
            
            if not exploitable_findings:
                logger.warning(
                    f"No exploitable findings to remediate",
                    total_findings=len(findings),
                    findings_statuses=[f.status for f in findings]
                )
                return []
            
            logger.info(
                f"Planning remediations for {len(exploitable_findings)} findings",
                validated_count=len([f for f in findings if f.status == 'validated']),
                new_count=len([f for f in findings if f.status == 'new'])
            )
            
            # Get remediation guidance from docs
            remediation_plans = []
            
            for finding in exploitable_findings:
                # Get remediation guidance from AWS docs MCP server
                # Temporarily bypass docs MCP due to parameter issues; use fallback guidance
                guidance = {
                    "service": finding.service,
                    "title": finding.title,
                    "fallback_guidance": "Use AWS security best practices for this service"
                }
                
                # Plan remediation using Claude
                plan = await self.planner.plan_remediation(finding, guidance, run)
                remediation_plans.append(plan)
                
                # Log plan details for debugging
                logger.info(
                    f"Remediation plan created",
                    plan_id=plan.id,
                    finding_id=finding.id,
                    mcp_action=plan.mcp_call.get('action', 'unknown'),
                    has_payload=bool(plan.mcp_call.get('payload', {}))
                )
            
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
            # Ensure MCP servers are installed/available
            try:
                await mcp_manager.ensure_servers_installed()
            except Exception as e:
                logger.warning("MCP server installation check failed", error=str(e))
            if not remediation_plans:
                logger.warning("No remediation plans to execute - nothing will be fixed!")
                return []
            
            logger.info(
                f"Starting remediation execution",
                plan_count=len(remediation_plans),
                dry_run=dry_run
            )
            
            # Execute remediations concurrently with limits
            semaphore = asyncio.Semaphore(self.settings.max_concurrent_remediations)
            
            # Start MCP clients once for all remediations (shared instance)
            ccapi_started = False
            if self.ccapi_client:
                try:
                    await self.ccapi_client.start()
                    ccapi_started = True
                    logger.info("CCAPI MCP server started for remediation phase")
                except Exception as e:
                    logger.warning(f"Failed to start CCAPI MCP server: {e}")
            
            async def execute_remediation(plan: RemediationPlan) -> Finding:
                async with semaphore:
                    try:
                        logger.info(
                            "Starting remediation execution",
                            plan_id=plan.id,
                            finding_id=plan.finding_id,
                            mcp_server=plan.mcp_server,
                            action=plan.mcp_call.get('action', 'unknown'),
                            dry_run=dry_run
                        )
                        
                        # Check if Claude already executed the fix via MCP tools
                        planned_change = plan.planned_change or {}
                        actual_tool_calls = planned_change.get('actual_tool_calls', [])
                        claude_already_executed = False
                        
                        for tool_call in actual_tool_calls:
                            tool_name = tool_call.get('tool', '')
                            if 'update_resource' in tool_name.lower():
                                claude_already_executed = True
                                logger.info(
                                    "Claude already executed update_resource during planning",
                                    plan_id=plan.id,
                                    tool_name=tool_name
                                )
                                # Extract result from tool call
                                tool_result = tool_call.get('result', {})
                                result = {
                                    "status": "executed_by_claude",
                                    "tool_call": tool_name,
                                    "claude_execution": True,
                                    "result": tool_result
                                }
                                break
                        
                        # If Claude already executed it, skip re-execution
                        if claude_already_executed:
                            logger.info(
                                "✅ Claude already executed update_resource - fix is done!",
                                plan_id=plan.id
                            )
                        elif plan.mcp_call.get('action') is None or plan.mcp_call.get('payload', {}).get('error'):
                            # Claude failed to call update_resource - cannot proceed
                            error_msg = plan.mcp_call.get('payload', {}).get('error', 'Claude did not call ccapi_update_resource')
                            logger.error(
                                "❌ Cannot execute remediation - Claude did not call update_resource",
                                plan_id=plan.id,
                                error=error_msg
                            )
                            raise RuntimeError(f"Remediation failed: {error_msg}. Claude must call ccapi_update_resource directly.")
                        elif plan.mcp_server == 'ccapi' and self.ccapi_client and ccapi_started:
                            try:
                                # Get the action and payload from mcp_call
                                action = plan.mcp_call.get('action', '')
                                payload = plan.mcp_call.get('payload', {})
                                
                                if not action:
                                    raise ValueError("Remediation plan has no action specified")
                                if not payload:
                                    raise ValueError("Remediation plan has no payload")
                                
                                logger.info(
                                    "Executing remediation via MCP (Claude didn't execute it directly)",
                                    plan_id=plan.id,
                                    action=action,
                                    payload_keys=list(payload.keys()) if isinstance(payload, dict) else None
                                )
                                
                                # Generic MCP tool call - no hardcoded methods needed
                                # The action should be an MCP tool name (e.g., 'update_resource')
                                result = await self.ccapi_client.call_tool(
                                    action,
                                    payload
                                )
                                
                                logger.info(
                                    "Remediation executed successfully",
                                    plan_id=plan.id,
                                    dry_run=dry_run,
                                    executed_by_claude=claude_already_executed,
                                    result_type=type(result).__name__,
                                    result_keys=list(result.keys()) if isinstance(result, dict) else None
                                )
                                
                            except Exception as e:
                                logger.error(
                                    "Remediation MCP call failed",
                                    error=str(e),
                                    error_type=type(e).__name__,
                                    plan_id=plan.id,
                                    action=plan.mcp_call.get('action', 'unknown'),
                                    exc_info=True
                                )
                                raise
                        elif plan.mcp_server == 'ccapi' and not ccapi_started:
                            error_msg = "CCAPI MCP server not available - failed to start"
                            logger.error(error_msg, plan_id=plan.id)
                            raise RuntimeError(error_msg)
                        else:
                            error_msg = f"Unsupported MCP server: {plan.mcp_server} or client not available"
                            logger.error(error_msg, plan_id=plan.id)
                            raise ValueError(error_msg)
                        
                        # Mark as executed
                        if not dry_run:
                            audit_ref = result.get('audit_ref') or result.get('security_group_id') or result.get('request_token', '')
                            plan.execute(audit_ref)
                            logger.info("Remediation plan marked as executed", plan_id=plan.id, audit_ref=audit_ref)
                        else:
                            logger.info("DRY RUN: Remediation plan would be marked as executed", plan_id=plan.id)
                        
                        # Update finding status
                        finding = await self._get_finding_by_id(plan.finding_id)
                        if finding:
                            if not dry_run:
                                finding.update_status('remediated')
                                logger.info("Finding status updated to remediated", finding_id=finding.id)
                            else:
                                logger.info("DRY RUN: Finding status would be updated to remediated", finding_id=finding.id)
                        else:
                            logger.warning("Finding not found", finding_id=plan.finding_id)
                        
                        # Store remediation result
                        async with DatabaseSession() as db_session:
                            # Store remediation in database
                            pass
                        
                        return finding
                        
                    except Exception as e:
                        error_msg = f"Remediation failed: {str(e)}"
                        logger.error(
                            "Remediation execution failed",
                            error=str(e),
                            error_type=type(e).__name__,
                            plan_id=plan.id,
                            finding_id=plan.finding_id,
                            exc_info=True
                        )
                        plan.fail(error_msg)
                        # Don't raise - continue with other remediations
                        return None
            
            # Execute all remediations
            results = await asyncio.gather(*[execute_remediation(plan) for plan in remediation_plans], return_exceptions=True)
            
            # Stop MCP client after all remediations complete
            if ccapi_started and self.ccapi_client:
                try:
                    await self.ccapi_client.stop()
                    logger.info("CCAPI MCP server stopped after remediation phase")
                except Exception as e:
                    logger.warning(f"Error stopping CCAPI MCP server: {e}")
            
            # Filter out None results (failed remediations)
            successful_remediations = [r for r in results if r is not None and not isinstance(r, Exception)]
            failed_remediations = [r for r in results if r is None or isinstance(r, Exception)]
            
            logger.info(
                f"Remediation phase completed",
                successful=len(successful_remediations),
                failed=len(failed_remediations),
                total=len(remediation_plans)
            )
            
            return successful_remediations
            
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
        """Get a finding by ID from cache or database."""
        # First check cache
        if finding_id in self._findings_cache:
            return self._findings_cache[finding_id]
        
        # Try database lookup
        try:
            async with DatabaseSession() as session:
                # This would query the database
                # For now, return None if not in cache
                pass
        except Exception as e:
            logger.warning(f"Database lookup failed for finding {finding_id}: {e}")
        
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

