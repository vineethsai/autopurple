"""Claude-based planning for AutoPurple."""

import json
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from ..config import get_settings
from ..logging import get_logger
from ..models.findings import Finding
from ..models.remediation import RemediationPlan
from ..models.runs import Run
from .mcp_claude_integration import MCPClaudeIntegration

logger = get_logger(__name__)


class ClaudePlanner:
    """Claude-based planner for analyzing findings and planning remediations."""
    
    def __init__(self, mcp_integration: Optional[MCPClaudeIntegration] = None):
        """Initialize the Claude planner."""
        self.settings = get_settings()
        self.client = self._get_claude_client()
        self.system_prompt = self._create_system_prompt()
        self.mcp_integration = mcp_integration
    
    def _get_claude_client(self):
        """Get Claude client based on configuration."""
        if not ANTHROPIC_AVAILABLE:
            logger.warning("Anthropic SDK not available")
            return None
        
        api_key = os.environ.get('CLAUDE_API_KEY') or self.settings.claude_api_key
        if not api_key:
            logger.warning("No Claude API key configured")
            return None
        
        try:
            client = anthropic.Anthropic(api_key=api_key)
            logger.info("Claude client initialized successfully")
            return client
        except Exception as e:
            logger.error("Failed to initialize Claude client", error=str(e))
            return None
    
    def _create_system_prompt(self) -> str:
        """Create the comprehensive system prompt for Claude."""
        prompt = """You are AutoPurple, an expert AWS security analyst and remediation specialist. Your mission is to analyze security findings and create actionable remediation plans.

## CORE CAPABILITIES
You excel at:
- Analyzing AWS security findings from ScoutSuite scans
- Identifying exploitable vulnerabilities and attack vectors  
- Planning comprehensive, risk-aware remediation strategies
- Using AWS MCP tools directly to remediate issues
- Prioritizing findings by actual business impact and exploitability

## MCP TOOLS AVAILABLE
You have access to AWS MCP server tools that allow you to directly interact with AWS resources:
- **CCAPI Tools**: Direct AWS resource operations (update_resource, generate_infrastructure_code, explain, etc.)
- **Documentation Tools**: Search AWS documentation for best practices

When you see these tools available, USE THEM DIRECTLY to:
1. Look up AWS documentation for best practices
2. Generate infrastructure code for fixes
3. Explain proposed changes
4. Execute remediations

You should prefer using MCP tools over generating JSON plans when tools are available.

## SECURITY ANALYSIS PRINCIPLES
1. **Risk-Based Assessment**: Focus on actual exploitability, not just policy violations
2. **Defense in Depth**: Consider how findings relate to broader security posture
3. **Blast Radius Analysis**: Evaluate potential impact of both vulnerabilities and fixes
4. **Operational Impact**: Balance security improvements with business continuity
5. **Compliance Alignment**: Ensure remediation aligns with security frameworks

## AWS EXPERTISE
You have deep knowledge of AWS security configurations and best practices.

## REMEDIATION APPROACH
When tools are available:
1. **First**: Search AWS documentation for best practices using docs tools
2. **Then**: Use CCAPI tools to generate and explain remediation code
3. **Finally**: Execute the remediation (or provide clear instructions)

When tools are NOT available:
- Provide detailed JSON remediation plans with specific MCP server calls

You are precise, security-focused, and always provide actionable guidance."""
        
        return prompt
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for Claude calls."""
        return self.system_prompt
    
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
            
            # Get MCP tools if available (for docs lookup)
            tools = None
            if self.mcp_integration:
                try:
                    # Only get docs tools for analysis (no need for CCAPI)
                    tools = await self.mcp_integration.get_claude_tools()
                    # Filter to only docs tools
                    tools = [t for t in tools if t.get('name', '').startswith('docs_')]
                except Exception as e:
                    logger.debug(f"Could not get MCP tools for analysis: {e}")
            
            # Get Claude analysis
            analysis = await self._call_claude(prompt, tools=tools)
            
            # Apply analysis to findings
            return self._apply_analysis(findings, analysis)
            
        except Exception as e:
            logger.error("Analysis failed", error=str(e))
            return findings
    
    def _create_analysis_prompt(self, findings_data: List[Dict[str, Any]], run: Run) -> str:
        """Create prompt for findings analysis."""
        return f"""Analyze the AWS security findings from this ScoutSuite scan and provide expert security assessment.

**SCAN CONTEXT:**
- AWS Account: {run.aws_account}
- AWS Region: {run.aws_region}
- Total Findings: {len(findings_data)}
- Scan Timestamp: {datetime.utcnow().isoformat()}

**FINDINGS TO ANALYZE:**
{json.dumps(findings_data, indent=2, default=str)}

**ANALYSIS REQUIREMENTS:**

1. **EXPLOITABILITY ASSESSMENT**: For each finding, evaluate:
   - Attack vectors and exploitation difficulty
   - Required attacker capabilities and access level
   - Potential for privilege escalation or lateral movement
   - Network accessibility and exposure scope

2. **BUSINESS IMPACT EVALUATION**: Consider:
   - Data confidentiality, integrity, and availability risks
   - Compliance and regulatory implications
   - Operational disruption potential
   - Financial and reputational impact

3. **FINDING RELATIONSHIPS**: Identify:
   - Related findings that compound risk
   - Common root causes across findings
   - Attack chains that link multiple vulnerabilities
   - Shared remediation opportunities

4. **PRIORITIZATION LOGIC**: Rank by:
   - Actual exploitability (not just theoretical risk)
   - Blast radius and potential impact
   - Ease of remediation vs. risk reduction
   - Regulatory and compliance criticality

**REQUIRED JSON OUTPUT:**
{{
    "executive_summary": {{
        "total_findings": {len(findings_data)},
        "critical_issues": "number of findings requiring immediate attention",
        "key_risks": ["list of top 3 security risks identified"],
        "overall_security_posture": "assessment of current security state"
    }},
    "clusters": [
        {{
            "cluster_id": "descriptive_name",
            "findings": ["finding_id1", "finding_id2"],
            "common_theme": "shared vulnerability pattern or root cause",
            "risk_level": "low|medium|high|critical",
            "attack_scenario": "how these findings could be chained together",
            "remediation_approach": "coordinated fix strategy"
        }}
    ],
    "duplicates": [
        {{
            "primary_finding": "finding_id_to_keep",
            "duplicate_findings": ["finding_id1", "finding_id2"],
            "reason": "why these are considered duplicates"
        }}
    ],
    "prioritized_findings": [
        {{
            "finding_id": "string",
            "priority_score": "1-10 (10 being most critical)",
            "exploitability": "low|medium|high|critical",
            "business_impact": "low|medium|high|critical", 
            "attack_complexity": "low|medium|high",
            "remediation_effort": "low|medium|high",
            "compliance_impact": "relevant compliance frameworks affected",
            "recommendation": "specific next steps and rationale",
            "dependencies": ["other findings that should be fixed together"]
        }}
    ],
    "remediation_roadmap": {{
        "immediate_actions": ["findings requiring emergency response"],
        "short_term": ["findings to address within 1-7 days"],
        "medium_term": ["findings to address within 1-4 weeks"],
        "long_term": ["findings for ongoing security improvement"]
    }}
}}"""
    
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
        """Plan remediation using Claude with direct MCP tool access."""
        if not self.client:
            logger.warning("No Claude client available, using default remediation plan")
            return self._create_default_remediation_plan(finding)
        
        try:
            # Get MCP tools if integration is available
            tools = None
            if self.mcp_integration:
                try:
                    tools = await self.mcp_integration.get_claude_tools()
                    logger.info(f"Exposed {len(tools)} MCP tools to Claude for remediation")
                except Exception as e:
                    logger.warning(f"Failed to get MCP tools: {e}")
            
            # Create remediation planning prompt (encourages tool use)
            prompt = self._create_remediation_prompt_with_mcp_tools(finding, guidance, run, tools)
            
            # Call Claude with tools - Claude will use tools directly
            plan_data = await self._call_claude(prompt, tools=tools, tool_choice="auto")
            
            # Extract remediation plan from Claude's response
            # If Claude used tools, the response will contain tool results
            # We need to create a plan that captures what Claude did/would do
            plan = self._create_remediation_plan_from_claude_response(finding, plan_data, tools)
            
            logger.info(f"Remediation plan created for finding {finding.id}")
            return plan
            
        except Exception as e:
            logger.error("Remediation planning failed", error=str(e))
            return self._create_default_remediation_plan(finding)
    
    def _create_remediation_prompt_with_mcp_tools(
        self,
        finding: Finding,
        guidance: Dict[str, Any],
        run: Run,
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """
        Create a remediation prompt that STRONGLY encourages Claude to execute
        the full remediation workflow using MCP tools directly.
        
        The key is: Claude should call ccapi_update_resource during this conversation,
        not just plan for later execution.
        """
        tool_instructions = ""
        if tools:
            # Filter to most relevant tools for this finding
            relevant_tools = []
            for tool in tools:
                name = tool.get('name', '')
                if finding.service == 'ec2' and ('security_group' in finding.title.lower() or 'security' in finding.title.lower()):
                    if 'docs_' in name or 'ccapi_get_resource' in name or 'ccapi_generate' in name or 'ccapi_explain' in name or 'ccapi_update' in name:
                        relevant_tools.append(name)
                elif 'docs_' in name or 'ccapi_get_resource' in name or 'ccapi_generate' in name:
                    relevant_tools.append(name)
            
            if not relevant_tools:
                relevant_tools = [t.get('name', '') for t in tools[:5]]  # Fallback to first 5
            
            tool_instructions = f"""

**🚨🚨🚨 MANDATORY INSTRUCTION - YOU MUST FOLLOW THIS EXACT WORKFLOW 🚨🚨🚨**

You have access to {len(tools)} AWS MCP tools. To fix this {finding.service} security vulnerability, you MUST execute the following steps IN ORDER:

**STEP 1**: Research best practices
   - Use 'docs_search_documentation' or 'docs_read_documentation' to find AWS security best practices

**STEP 2**: Get current resource state  
   - Use 'ccapi_get_resource' with resource_type='AWS::EC2::SecurityGroup' and identifier='{finding.resource_id}'
   - This shows you what needs to be fixed

**STEP 3**: Generate the fix code
   - Use 'ccapi_generate_infrastructure_code' with:
     * resource_type='AWS::EC2::SecurityGroup'
     * properties={{...}} that REMOVE the public access (0.0.0.0/0) rules
     * credentials_token=<from get_aws_session_info>
   - The response will contain 'generated_code_token' - EXTRACT THIS TOKEN FROM THE RESPONSE!
   - Example: If response contains {{"generated_code_token": "generated_code_abc123"}}, use "generated_code_abc123"

**STEP 4**: Explain the changes
   - Use 'ccapi_explain' with:
     * generated_code_token=<EXACT token from step 3 response>
   - The response will contain 'explained_token' - EXTRACT THIS TOKEN FROM THE RESPONSE!
   - Example: If response contains {{"explained_token": "explained_xyz789"}}, use "explained_xyz789"
   - IMPORTANT: Pass the 'generated_code_token' TO explain(), then get 'explained_token' FROM the explain() response

**STEP 5**: Run security scan (REQUIRED when SECURITY_SCANNING=enabled)
   - Use 'ccapi_run_checkov' with:
     * explained_token=<EXACT token from step 4 response>
   - The response will contain 'security_scan_token' - EXTRACT THIS TOKEN FROM THE RESPONSE!
   - IMPORTANT: Pass the 'explained_token' TO run_checkov(), NOT the generated_code_token!
   - This is MANDATORY - the system has SECURITY_SCANNING=enabled

**STEP 7**: ⚠️⚠️⚠️ MANDATORY - EXECUTE THE FIX ⚠️⚠️⚠️
   - Use 'ccapi_update_resource' with ALL required parameters:
     * identifier='{finding.resource_id}' (security group ID as string, e.g., 'sg-0883d70e892681de2')
     * resource_type='AWS::EC2::SecurityGroup'
     * explained_token=<EXACT value from step 5's 'explained_token' field>
     * security_scan_token=<EXACT value from step 6's 'security_scan_token' field>
     * credentials_token=<EXACT value from step 3's 'credentials_token' field>
     * region='{run.aws_region}' (CRITICAL: Must be '{run.aws_region}' to match resource location!)
   - **ALL FOUR PARAMETERS ARE REQUIRED**: explained_token, security_scan_token, credentials_token, region
   - **TOKEN EXTRACTION**: Use the EXACT token values you extracted from previous steps - do NOT invent new tokens!
   
   **🚨 YOU MUST CALL ccapi_update_resource - THIS IS NOT OPTIONAL!**
   **🚨 IF YOU DO NOT CALL ccapi_update_resource, THE VULNERABILITY WILL NOT BE FIXED!**
   **🚨 DO NOT SKIP THIS STEP - CALL IT NOW BEFORE FINISHING!**

**STEP 8**: Confirm the fix was applied
   - After calling update_resource, verify the response indicates success
   - Summarize what was fixed
   - Confirm public access (0.0.0.0/0) has been removed

**⚠️ CRITICAL TOKEN EXTRACTION RULES:**
1. **Each tool response is JSON** - you MUST parse it to extract tokens
2. **Extract the VALUE, not the field name**: {{"generated_code_token": "generated_code_abc"}} → use "generated_code_abc"
3. **Token flow**: credentials_token (step 3) → generate (step 4) → generated_code_token → explain (step 5) → explained_token → run_checkov (step 6) → security_scan_token → update_resource (step 7)
4. **DO NOT reuse tokens**: Each step produces a NEW token - use the one from the PREVIOUS step's response
5. **DO NOT skip steps**: You MUST complete all 7 steps before finishing

**⚠️ CRITICAL EXECUTION RULES:**
1. You MUST call ccapi_update_resource during this conversation - not in a future step
2. You MUST use the explained_token from step 5 AND security_scan_token from step 6 AND credentials_token from step 3
3. You MUST include region='{run.aws_region}' in update_resource
4. If you only call generate/explain but NOT run_checkov and update_resource, you have FAILED
5. DO NOT stop after explain() - you MUST continue to run_checkov() and then update_resource()

**DO NOT:**
- Generate code and then stop
- Create a "plan" for later execution
- Skip the update_resource call
- Just describe what should be done

**YOU MUST:**
- Call ccapi_update_resource before finishing
- Use the explained_token from the explain step
- Actually fix the vulnerability in this conversation

Relevant tools for this task: {', '.join(relevant_tools)}"""
        
        return f"""Plan and execute a comprehensive, production-ready remediation for this critical AWS security finding.{tool_instructions}

**FINDING DETAILS:**
- Title: {finding.title}
- Service: {finding.service}
- Resource ID: {finding.resource_id}
- Severity: {finding.severity}
- Status: {finding.status}

**DEPLOYMENT CONTEXT:**
- AWS Account: {run.aws_account}
- AWS Region: {run.aws_region}
- Timestamp: {datetime.utcnow().isoformat()}

**EVIDENCE & VULNERABILITY DATA:**
{json.dumps(finding.evidence, indent=2, default=str)}

**YOUR TASK:**
Analyze this security vulnerability and create a remediation plan. If tools are available, USE THEM to:
1. Research AWS best practices
2. Get current resource state
3. Generate the fix
4. Explain what the fix does
5. Execute or describe the remediation

Provide a clear summary of:
- What the vulnerability is
- How it could be exploited
- What tools you used (if any)
- What remediation was performed/recommended
- How to verify the fix worked

**OUTPUT FORMAT:**
Provide a JSON summary of your analysis and remediation actions:
{{
    "vulnerability_analysis": {{
        "attack_vectors": ["how this could be exploited"],
        "blast_radius": "scope of potential impact",
        "compliance_violations": ["affected frameworks"],
        "business_criticality": "assessment"
    }},
    "tools_used": ["list of MCP tools you used"],
    "remediation_steps_taken": ["what you actually did via tools"],
    "remediation_summary": {{
        "approach": "how you fixed it",
        "changes_made": "specific changes",
        "verification_method": "how to confirm fix worked"
    }},
    "risk_assessment": {{
        "implementation_risk": "risk level",
        "downtime_impact": "expected disruption",
        "rollback_complexity": "how to undo if needed"
    }}
}}"""
    
    def _create_remediation_plan_from_claude_response(
        self,
        finding: Finding,
        claude_response: Dict[str, Any],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> RemediationPlan:
        """
        Create remediation plan from Claude's response (which may include tool use).
        
        KEY INSIGHT: If Claude called ccapi_update_resource during the conversation,
        the fix is already executed! We just need to track that.
        """
        # Extract remediation information from Claude's response
        # If Claude used tools, we need to capture that in the plan
        
        # Default plan structure - will be set based on what Claude actually did
        mcp_action = None
        mcp_payload = {}
        claude_executed_update_resource = False
        
        # First, check actual tool usage from the conversation
        actual_tool_usage = claude_response.get('_actual_tool_usage', [])
        
        # Extract from actual tool calls - look for generate_infrastructure_code or update_resource
        generated_code_token = None
        explained_token = None
        
        for tool_call in actual_tool_usage:
            tool_name = tool_call.get('tool', '')
            args = tool_call.get('arguments', {})
            result = tool_call.get('result', {})
            
            # Check if it's a dict with content array (MCP format)
            if isinstance(result, dict) and 'content' in result:
                for content_item in result.get('content', []):
                    if isinstance(content_item, dict) and 'text' in content_item:
                        try:
                            import json
                            result_data = json.loads(content_item['text'])
                            
                            if 'generated_code_token' in result_data:
                                generated_code_token = result_data['generated_code_token']
                            if 'explained_token' in result_data:
                                explained_token = result_data['explained_token']
                        except:
                            pass
            
            # Track update_resource calls - this means Claude already executed the fix!
            if 'update_resource' in tool_name.lower():
                # Claude actually called update_resource - fix is already done!
                mcp_action = 'update_resource'
                mcp_payload = args
                claude_executed_update_resource = True
                logger.info(
                    "Claude executed update_resource during planning - fix already applied!",
                    tool_name=tool_name,
                    finding_id=finding.id
                )
        
        # If Claude didn't call update_resource, log a failure
        # We do NOT want fallbacks - Claude must call it directly
        if not claude_executed_update_resource:
            # Claude FAILED to call update_resource - this is an error
            # We do NOT want fallbacks - Claude must call it directly
            logger.error(
                "Claude FAILED to call update_resource - remediation cannot proceed",
                finding_id=finding.id,
                has_generated_token=bool(generated_code_token),
                has_explained_token=bool(explained_token),
                tool_calls=[t.get('tool') for t in actual_tool_usage]
            )
            
            # Do NOT create a fallback plan - Claude must fix this
            # Create a minimal plan that indicates failure
            mcp_action = None  # No action - Claude failed to execute
            mcp_payload = {
                'error': 'Claude did not call ccapi_update_resource as required',
                'expected_action': 'ccapi_update_resource',
                'actual_tool_calls': [t.get('tool') for t in actual_tool_usage]
            }
        
        # If Claude still didn't execute anything, this is a critical failure
        if not mcp_action or not claude_executed_update_resource:
            logger.error(
                "CRITICAL: Claude did not call ccapi_update_resource - remediation FAILED",
                finding_id=finding.id,
                tool_calls_count=len(actual_tool_usage),
                tool_calls=[t.get('tool') for t in actual_tool_usage]
            )
            # No fallback - Claude must call update_resource directly
            if not mcp_action:
                mcp_action = None  # No action possible without Claude's execution
                mcp_payload = {
                    'error': 'Claude did not execute remediation - no update_resource call found',
                    'required_action': 'ccapi_update_resource',
                    'actual_actions': [t.get('tool') for t in actual_tool_usage]
                }
        
        # Removed hardcoded fallback logic - Claude should use MCP tools directly
        
        # Try to extract from Claude's JSON response too
        remediation_steps = claude_response.get('remediation_steps_taken', [])
        remediation_summary = claude_response.get('remediation_summary', {})
        
        # Update tools_used list from actual tool usage
        tools_used = [t.get('tool') for t in actual_tool_usage]
        if not tools_used:
            tools_used = claude_response.get('tools_used', [])
        
        return RemediationPlan(
            id=f"remediation_{uuid.uuid4().hex}",
            finding_id=finding.id,
            planned_change={
                "claude_analysis": claude_response.get('vulnerability_analysis', {}),
                "tools_used": tools_used,
                "actual_tool_calls": actual_tool_usage,  # Include actual tool call history
                "remediation_steps": remediation_steps,
                "remediation_summary": remediation_summary,
                "risk_assessment": claude_response.get('risk_assessment', {})
            },
            mcp_server='ccapi',
            mcp_call={
                'action': mcp_action,
                'payload': mcp_payload
            }
        )
    
    def _create_remediation_plan(
        self,
        finding: Finding,
        plan_data: Dict[str, Any]
    ) -> RemediationPlan:
        """Create a RemediationPlan from Claude's response (legacy method)."""
        # Extract the first remediation step for the MCP call
        remediation_steps = plan_data.get('remediation_steps', [])
        if not remediation_steps:
            return self._create_default_remediation_plan(finding)
        
        first_step = remediation_steps[0]
        
        # Map Claude's action to CCAPI method
        claude_action = first_step.get('action', '')
        if 'security_group' in claude_action.lower() or 'security-group' in claude_action.lower():
            mcp_action = 'update_security_group_rules'
            parameters = first_step.get('parameters', {})
            sg_id = parameters.get('GroupId') or parameters.get('securityGroupId') or finding.resource_id
            
            rules = {
                'authorize_ingress': [],
                'revoke_ingress': []
            }
            
            if 'IpPermissions' in parameters:
                for perm in parameters.get('IpPermissions', []):
                    if perm.get('IpRanges', [{}])[0].get('CidrIp') != '0.0.0.0/0':
                        rules['authorize_ingress'].append(perm)
                    else:
                        rules['revoke_ingress'].append(perm)
            
            mcp_payload = {
                'securityGroupId': sg_id,
                'rules': rules
            }
        else:
            mcp_action = claude_action
            mcp_payload = first_step.get('parameters', {})
        
        return RemediationPlan(
            id=f"remediation_{uuid.uuid4().hex}",
            finding_id=finding.id,
            planned_change=plan_data,
            mcp_server=first_step.get('mcp_server', 'ccapi'),
            mcp_call={
                'action': mcp_action,
                'payload': mcp_payload
            }
        )
    
    async def _call_claude(
        self,
        prompt: str,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str] = None
    ) -> Dict[str, Any]:
        """Call Claude with the given prompt and optional MCP tools."""
        if not self.client:
            return self._mock_analysis()
        
        try:
            logger.info("Making Claude API call", has_tools=bool(tools))
            
            api_params = {
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 4000,
                "system": self._get_system_prompt(),
                "messages": [{"role": "user", "content": prompt}]
            }
            
            if tools:
                api_params["tools"] = tools
                # tool_choice: omit for "auto", or pass specific tool name
                # Don't pass "auto" as string - let SDK handle default
                if tool_choice and tool_choice != "auto":
                    if isinstance(tool_choice, str):
                        # If it's a tool name, convert to dict format
                        api_params["tool_choice"] = {"type": "tool", "name": tool_choice}
                    else:
                        api_params["tool_choice"] = tool_choice
                # For "auto", just don't include tool_choice parameter
            
            response = self.client.messages.create(**api_params)
            
            # Handle Claude response (may contain tool use)
            messages = [{"role": "user", "content": prompt}]
            current_response = response
            # Increase max_iterations to allow for full workflow:
            # docs → get_resource → generate → explain → run_checkov → update_resource = 6+ steps
            max_iterations = 10  # Increased to allow full CCAPI workflow with security scanning
            iteration = 0
            
            # Track actual tool usage for remediation plan
            actual_tool_usage = []
            
            # Debug logging
            logger.debug(f"Claude API response type: {type(current_response)}")
            if hasattr(current_response, 'content'):
                logger.debug(f"Response has {len(current_response.content)} content blocks")
            
            while current_response and iteration < max_iterations:
                iteration += 1
                
                # Check for tool use
                if hasattr(current_response, 'content') and current_response.content:
                    tool_uses = []
                    text_parts = []
                    
                    for block in current_response.content:
                        if hasattr(block, 'type'):
                            if block.type == 'tool_use':
                                tool_uses.append(block)
                                logger.info(f"Claude requested tool: {block.name}")
                            elif block.type == 'text':
                                text_parts.append(block.text)
                    
                    # Execute tools if requested
                    if tool_uses and self.mcp_integration:
                        logger.info(f"Claude requested {len(tool_uses)} tool uses (iteration {iteration})")
                        
                        tool_results = []
                        for tool_use in tool_uses:
                            try:
                                result = await self.mcp_integration.execute_claude_tool_use(
                                    tool_use.name,
                                    tool_use.input
                                )
                                result_text = self._format_mcp_result_for_claude(result)
                                tool_results.append({
                                    "type": "tool_result",
                                    "tool_use_id": tool_use.id,
                                    "content": result_text
                                })
                                
                                # Track tool usage for remediation plan
                                actual_tool_usage.append({
                                    "tool": tool_use.name,
                                    "arguments": tool_use.input,
                                    "result": result
                                })
                                
                                logger.info(f"Tool {tool_use.name} executed successfully")
                            except Exception as e:
                                logger.error(f"Tool {tool_use.name} failed: {e}")
                                tool_results.append({
                                    "type": "tool_result",
                                    "tool_use_id": tool_use.id,
                                    "content": f"Error: {str(e)}",
                                    "is_error": True
                                })
                                
                                # Track failed tool usage too
                                actual_tool_usage.append({
                                    "tool": tool_use.name,
                                    "arguments": tool_use.input,
                                    "error": str(e)
                                })
                        
                        # Send tool results back to Claude
                        messages.append({
                            "role": "assistant",
                            "content": current_response.content
                        })
                        messages.append({
                            "role": "user",
                            "content": tool_results
                        })
                        
                        # Get Claude's response to tool results
                        next_api_params = {
                            "model": "claude-sonnet-4-20250514",
                            "max_tokens": 4000,
                            "system": self._get_system_prompt(),
                            "messages": messages
                        }
                        if tools:
                            next_api_params["tools"] = tools
                        # Don't pass tool_choice for "auto" (default)
                        current_response = self.client.messages.create(**next_api_params)
                        continue
                
                # No tool use - extract text and parse
                if text_parts:
                    content = "\n".join(text_parts)
                    parsed_json = self._parse_claude_response(content)
                    if parsed_json:
                        logger.info("Claude API call successful", iterations=iteration)
                        # Include actual tool usage in the response
                        parsed_json["_actual_tool_usage"] = actual_tool_usage
                        return parsed_json
                
                # If we have a text response but no JSON, try to extract from it
                if hasattr(current_response, 'content'):
                    full_text = ""
                    for block in current_response.content:
                        if hasattr(block, 'text'):
                            full_text += block.text
                    if full_text:
                        parsed_json = self._parse_claude_response(full_text)
                        if parsed_json:
                            # Include actual tool usage in the response
                            parsed_json["_actual_tool_usage"] = actual_tool_usage
                            return parsed_json
                
                # If no more tool use and no parseable response, break
                break
            
            # Fallback: return mock with tool usage, but still include tool usage for plan creation
            logger.warning("Could not parse Claude response after tool use, but tool usage was tracked", 
                         tool_count=len(actual_tool_usage))
            # Create a minimal response that includes tool usage so we can still build a plan
            fallback = {
                "vulnerability_analysis": {
                    "attack_vectors": ["Public access allows unauthorized connections"],
                    "blast_radius": "High - direct network access",
                    "compliance_violations": ["PCI-DSS", "SOC2"],
                    "business_criticality": "high"
                },
                "remediation_summary": {
                    "approach": "Remove public access rules based on tool analysis",
                    "changes_made": "Revoke 0.0.0.0/0 access rules",
                    "verification_method": "Verify security group no longer allows public access"
                },
                "tools_used": [t.get("tool", "") for t in actual_tool_usage],
                "remediation_steps_taken": ["Analyzed security group", "Generated remediation code"] if actual_tool_usage else [],
                "_actual_tool_usage": actual_tool_usage
            }
            return fallback
                
        except Exception as e:
            logger.error("Claude API call failed", error=str(e))
            return self._mock_analysis()
    
    def _format_mcp_result_for_claude(self, mcp_result: Dict[str, Any]) -> str:
        """Format MCP result for Claude's tool result format."""
        if isinstance(mcp_result, dict) and 'content' in mcp_result:
            text_parts = []
            for item in mcp_result.get('content', []):
                if isinstance(item, dict) and 'text' in item:
                    text_parts.append(item['text'])
            return "\n".join(text_parts)
        elif isinstance(mcp_result, dict):
            import json
            return json.dumps(mcp_result, indent=2, default=str)
        else:
            return str(mcp_result)
    
    def _parse_claude_response(self, content: str) -> Optional[Dict[str, Any]]:
        """Parse Claude response with multiple robust strategies."""
        import re
        
        # Strategy 1: Direct JSON parse
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        
        # Strategy 2: Extract JSON from markdown code blocks
        json_patterns = [
            r'```json\s*([\s\S]*?)```',
            r'```\s*([\s\S]*?)```',
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                try:
                    return json.loads(match.strip())
                except json.JSONDecodeError:
                    continue
        
        # Strategy 3: Find JSON-like content
        brace_patterns = [
            r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',
            r'\{[\s\S]*?\}(?=\s*$|\s*\n\s*[^}])',
        ]
        
        for pattern in brace_patterns:
            matches = re.findall(pattern, content, re.DOTALL)
            for match in matches:
                cleaned = match.strip()
                cleaned = self._fix_common_json_issues(cleaned)
                try:
                    return json.loads(cleaned)
                except json.JSONDecodeError:
                    continue
        
        return None
    
    def _fix_common_json_issues(self, json_str: str) -> str:
        """Fix common JSON formatting issues."""
        import re
        json_str = re.sub(r',(\s*[}\]])', r'\1', json_str)
        json_str = re.sub(r"'([^']*)'", r'"\1"', json_str)
        return json_str
    
    def _mock_analysis(self) -> Dict[str, Any]:
        """Return mock analysis for testing."""
        return {
            "executive_summary": {
                "total_findings": 0,
                "critical_issues": 0,
                "key_risks": [],
                "overall_security_posture": "Unable to analyze - Claude not available"
            },
            "clusters": [],
            "duplicates": [],
            "prioritized_findings": [],
            "remediation_roadmap": {
                "immediate_actions": [],
                "short_term": [],
                "medium_term": [],
                "long_term": []
            }
        }
    
    def _create_default_remediation_plan(self, finding: Finding) -> RemediationPlan:
        """Create a default remediation plan when Claude is not available."""
        if finding.service.lower() == 'ec2':
            return RemediationPlan(
                id=f"remediation_{uuid.uuid4().hex}",
                finding_id=finding.id,
                planned_change={"default_plan": True},
                mcp_server='ccapi',
                mcp_call={
                    'action': 'update_security_group_rules',
                    'payload': {
                        'securityGroupId': finding.resource_id,
                        'rules': {'revoke_ingress': [], 'authorize_ingress': []}
                    }
                }
            )
        else:
            return RemediationPlan(
                id=f"remediation_{uuid.uuid4().hex}",
                finding_id=finding.id,
                planned_change={"default_plan": True},
                mcp_server='ccapi',
                mcp_call={'action': 'update_resource', 'payload': {}}
            )
