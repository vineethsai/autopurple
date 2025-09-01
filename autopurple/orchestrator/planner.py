"""Claude-based planning for AutoPurple."""

import json
import uuid
from typing import Any, Dict, List, Optional

from ..config import get_settings
from ..logging import get_logger
from ..models.findings import Finding
from ..models.remediation import RemediationPlan
from ..models.runs import Run

logger = get_logger(__name__)


class ClaudePlanner:
    """Claude-based planner for analyzing findings and planning remediations."""
    
    def __init__(self):
        """Initialize the Claude planner."""
        self.settings = get_settings()
        self.client = self._get_claude_client()
    
    def _get_claude_client(self):
        """Get Claude client based on configuration."""
        # This would initialize the appropriate AI client
        # For now, return None to indicate no AI client available
        return None
    
    async def analyze_findings(self, findings: List[Finding], run: Run) -> List[Finding]:
        """Analyze findings using Claude to cluster, dedupe, and rank by exploitability."""
        if not self.client:
            logger.warning("No Claude client available, skipping analysis")
            return findings
        
        try:
            # Prepare findings for analysis
            findings_data = []
            for finding in findings:
                findings_data.append({
                    'id': finding.id,
                    'service': finding.service,
                    'title': finding.title,
                    'severity': finding.severity,
                    'evidence_summary': finding.evidence_summary
                })
            
            # Create analysis prompt
            prompt = self._create_analysis_prompt(findings_data, run)
            
            # Get Claude analysis
            analysis = await self._call_claude(prompt)
            
            # Apply analysis results
            analyzed_findings = self._apply_analysis(findings, analysis)
            
            logger.info(f"Analysis completed: {len(analyzed_findings)} findings analyzed")
            return analyzed_findings
            
        except Exception as e:
            logger.error("Analysis failed", error=str(e))
            return findings
    
    def _create_analysis_prompt(self, findings_data: List[Dict[str, Any]], run: Run) -> str:
        """Create prompt for findings analysis."""
        return f"""
You are an AWS security expert analyzing security findings from ScoutSuite.

Context:
- AWS Account: {run.aws_account}
- AWS Region: {run.aws_region}
- Total Findings: {len(findings_data)}

Findings to analyze:
{json.dumps(findings_data, indent=2)}

Please analyze these findings and provide:
1. Clustering: Group similar findings together
2. Deduplication: Identify duplicate findings
3. Prioritization: Rank by exploitability and business impact
4. Risk assessment: Evaluate the actual risk level

Return your analysis as JSON with the following structure:
{{
    "clusters": [
        {{
            "cluster_id": "string",
            "findings": ["finding_id1", "finding_id2"],
            "common_theme": "string",
            "risk_level": "low|medium|high|critical"
        }}
    ],
    "duplicates": [
        {{
            "primary_finding": "finding_id",
            "duplicate_findings": ["finding_id1", "finding_id2"]
        }}
    ],
    "prioritized_findings": [
        {{
            "finding_id": "string",
            "priority_score": 1-10,
            "exploitability": "low|medium|high|critical",
            "business_impact": "low|medium|high|critical",
            "recommendation": "string"
        }}
    ]
}}
"""
    
    async def _call_claude(self, prompt: str) -> Dict[str, Any]:
        """Call Claude with the given prompt."""
        if not self.client:
            # Return mock analysis for testing
            return self._mock_analysis()
        
        # This would make the actual API call to Claude
        # For now, return mock data
        return self._mock_analysis()
    
    def _mock_analysis(self) -> Dict[str, Any]:
        """Return mock analysis for testing."""
        return {
            "clusters": [
                {
                    "cluster_id": "cluster_1",
                    "findings": ["finding_1", "finding_2"],
                    "common_theme": "IAM policy issues",
                    "risk_level": "high"
                }
            ],
            "duplicates": [],
            "prioritized_findings": [
                {
                    "finding_id": "finding_1",
                    "priority_score": 8,
                    "exploitability": "high",
                    "business_impact": "high",
                    "recommendation": "Immediate remediation required"
                }
            ]
        }
    
    def _apply_analysis(self, findings: List[Finding], analysis: Dict[str, Any]) -> List[Finding]:
        """Apply analysis results to findings."""
        # This would apply the analysis results to the findings
        # For now, return findings as-is
        return findings
    
    async def plan_remediation(
        self,
        finding: Finding,
        guidance: Dict[str, Any],
        run: Run
    ) -> RemediationPlan:
        """Plan remediation for a finding using Claude."""
        if not self.client:
            logger.warning("No Claude client available, using default remediation plan")
            return self._create_default_remediation_plan(finding)
        
        try:
            # Create remediation planning prompt
            prompt = self._create_remediation_prompt(finding, guidance, run)
            
            # Get Claude remediation plan
            plan_data = await self._call_claude(prompt)
            
            # Create remediation plan
            plan = self._create_remediation_plan(finding, plan_data)
            
            logger.info(f"Remediation plan created for finding {finding.id}")
            return plan
            
        except Exception as e:
            logger.error("Remediation planning failed", error=str(e))
            return self._create_default_remediation_plan(finding)
    
    def _create_remediation_prompt(
        self,
        finding: Finding,
        guidance: Dict[str, Any],
        run: Run
    ) -> str:
        """Create prompt for remediation planning."""
        return f"""
You are an AWS security expert planning remediation for a security finding.

Context:
- AWS Account: {run.aws_account}
- AWS Region: {run.aws_region}
- Finding: {finding.title}
- Service: {finding.service}
- Severity: {finding.severity}
- Evidence: {finding.evidence_summary}

AWS Documentation Guidance:
{json.dumps(guidance, indent=2)}

Please create a detailed remediation plan that includes:
1. Pre-checks: What to verify before making changes
2. Remediation steps: Specific actions to take
3. Rollback plan: How to undo changes if needed
4. Success criteria: How to verify the fix worked
5. MCP calls: Exact MCP server calls with parameters

Return your plan as JSON with the following structure:
{{
    "pre_checks": [
        {{
            "check": "string",
            "method": "string",
            "expected_result": "string"
        }}
    ],
    "remediation_steps": [
        {{
            "step": "string",
            "mcp_server": "ccapi|cfn",
            "action": "string",
            "parameters": {{}},
            "description": "string"
        }}
    ],
    "rollback_plan": [
        {{
            "step": "string",
            "mcp_server": "ccapi|cfn",
            "action": "string",
            "parameters": {{}},
            "description": "string"
        }}
    ],
    "success_criteria": [
        {{
            "criterion": "string",
            "verification_method": "string"
        }}
    ],
    "risk_assessment": {{
        "blast_radius": "string",
        "downtime_impact": "string",
        "data_impact": "string"
    }}
}}
"""
    
    def _create_remediation_plan(
        self,
        finding: Finding,
        plan_data: Dict[str, Any]
    ) -> RemediationPlan:
        """Create a RemediationPlan from Claude's response."""
        # Extract the first remediation step for the MCP call
        remediation_steps = plan_data.get('remediation_steps', [])
        if not remediation_steps:
            return self._create_default_remediation_plan(finding)
        
        first_step = remediation_steps[0]
        
        return RemediationPlan(
            id=f"remediation_{uuid.uuid4().hex}",
            finding_id=finding.id,
            planned_change=plan_data,
            mcp_server=first_step.get('mcp_server', 'ccapi'),
            mcp_call={
                'action': first_step.get('action', ''),
                'payload': first_step.get('parameters', {})
            }
        )
    
    def _create_default_remediation_plan(self, finding: Finding) -> RemediationPlan:
        """Create a default remediation plan when Claude is not available."""
        # Create a basic plan based on the finding type
        if finding.service.lower() == 'iam':
            return RemediationPlan(
                id=f"remediation_{uuid.uuid4().hex}",
                finding_id=finding.id,
                planned_change={
                    'description': f'Default remediation for {finding.title}',
                    'method': 'manual_review_required'
                },
                mcp_server='ccapi',
                mcp_call={
                    'action': 'review_iam_policy',
                    'payload': {
                        'resource_id': finding.resource_id,
                        'finding_title': finding.title
                    }
                }
            )
        else:
            return RemediationPlan(
                id=f"remediation_{uuid.uuid4().hex}",
                finding_id=finding.id,
                planned_change={
                    'description': f'Default remediation for {finding.title}',
                    'method': 'manual_review_required'
                },
                mcp_server='cfn',
                mcp_call={
                    'action': 'review_resource',
                    'payload': {
                        'service': finding.service,
                        'resource_id': finding.resource_id,
                        'finding_title': finding.title
                    }
                }
            )

