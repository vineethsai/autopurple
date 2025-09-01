"""ScoutSuite adapter for AWS security discovery."""

import asyncio
import json
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import anyio
from tenacity import retry, stop_after_attempt, wait_exponential

from ..config import get_settings
from ..logging import get_logger
from ..models.findings import Finding, Severity

logger = get_logger(__name__)


class ScoutSuiteAdapter:
    """Adapter for ScoutSuite AWS security discovery."""
    
    def __init__(self, scoutsuite_path: Optional[str] = None):
        """Initialize the ScoutSuite adapter."""
        self.scoutsuite_path = scoutsuite_path or self._find_scoutsuite()
        self.settings = get_settings()
        
        if not self.scoutsuite_path:
            raise ValueError("ScoutSuite not found. Please install ScoutSuite or provide path.")
    
    def _find_scoutsuite(self) -> Optional[str]:
        """Find ScoutSuite installation."""
        # First try to import ScoutSuite as a module
        try:
            import ScoutSuite
            return "python -m ScoutSuite"
        except ImportError:
            pass
        
        # Try to find ScoutSuite in common locations
        possible_paths = [
            "scoutsuite",
            "ScoutSuite/scout.py",
            "external/ScoutSuite/scout.py",
            "/usr/local/bin/scoutsuite",
        ]
        
        for path in possible_paths:
            try:
                if Path(path).exists():
                    return path
            except (TypeError, ValueError):
                continue
        
        # Try to find via pip/conda
        try:
            result = subprocess.run(
                ["which", "scoutsuite"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        reraise=True
    )
    async def run_discovery(
        self,
        aws_profile: Optional[str] = None,
        aws_region: Optional[str] = None,
        *,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """Run ScoutSuite discovery on AWS account."""
        timeout = timeout or self.settings.scoutsuite_timeout
        
        # Build ScoutSuite command
        if self.scoutsuite_path.startswith("python -m"):
            # Module execution
            cmd = [
                "python", "-m", "ScoutSuite",
                "--provider", "aws",
                "--report-dir", "/tmp/scoutsuite_reports",
                "--report-name", f"autopurple_{uuid.uuid4().hex[:8]}",
                "--format", "json"
            ]
        else:
            # Direct executable
            cmd = [
                "python", self.scoutsuite_path,
                "--provider", "aws",
                "--report-dir", "/tmp/scoutsuite_reports",
                "--report-name", f"autopurple_{uuid.uuid4().hex[:8]}",
                "--format", "json"
            ]
        
        if aws_profile:
            cmd.extend(["--profile", aws_profile])
        
        if aws_region:
            cmd.extend(["--regions", aws_region])
        
        logger.info(
            "Starting ScoutSuite discovery",
            cmd=" ".join(cmd),
            timeout=timeout,
            profile=aws_profile,
            region=aws_region
        )
        
        try:
            # Run ScoutSuite in a thread to avoid blocking
            result = await anyio.to_thread.run_sync(
                self._run_scoutsuite_subprocess,
                cmd,
                timeout
            )
            
            logger.info(
                "ScoutSuite discovery completed",
                return_code=result.returncode,
                stdout_length=len(result.stdout),
                stderr_length=len(result.stderr)
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"ScoutSuite failed: {result.stderr}")
            
            return self._parse_scoutsuite_output(result.stdout)
            
        except Exception as e:
            logger.error(
                "ScoutSuite discovery failed",
                error=str(e),
                cmd=" ".join(cmd)
            )
            raise
    
    def _run_scoutsuite_subprocess(
        self,
        cmd: List[str],
        timeout: int
    ) -> subprocess.CompletedProcess:
        """Run ScoutSuite subprocess with timeout."""
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=self._get_environment()
        )
    
    def _get_environment(self) -> Dict[str, str]:
        """Get environment variables for ScoutSuite execution."""
        env = {}
        
        # Add AWS environment variables if configured
        if self.settings.aws_profile:
            env["AWS_PROFILE"] = self.settings.aws_profile
        if self.settings.aws_region:
            env["AWS_DEFAULT_REGION"] = self.settings.aws_region
        
        return env
    
    def _parse_scoutsuite_output(self, output: str) -> Dict[str, Any]:
        """Parse ScoutSuite JSON output."""
        try:
            # ScoutSuite might output multiple JSON objects or have extra output
            # Try to extract JSON from the output
            lines = output.strip().split('\n')
            json_lines = []
            
            for line in lines:
                line = line.strip()
                if line.startswith('{') and line.endswith('}'):
                    json_lines.append(line)
            
            if not json_lines:
                raise ValueError("No JSON output found in ScoutSuite output")
            
            # Parse the last JSON object (most recent results)
            data = json.loads(json_lines[-1])
            
            logger.info(
                "Parsed ScoutSuite output",
                services=list(data.get('services', {}).keys()),
                findings_count=self._count_findings(data)
            )
            
            return data
            
        except json.JSONDecodeError as e:
            logger.error("Failed to parse ScoutSuite JSON output", error=str(e))
            raise
    
    def _count_findings(self, data: Dict[str, Any]) -> int:
        """Count total findings in ScoutSuite output."""
        count = 0
        services = data.get('services', {})
        
        for service_name, service_data in services.items():
            if isinstance(service_data, dict):
                for resource_type, resources in service_data.items():
                    if isinstance(resources, dict):
                        for resource_id, resource_data in resources.items():
                            if isinstance(resource_data, dict):
                                # Count findings in this resource
                                findings = resource_data.get('findings', [])
                                if isinstance(findings, list):
                                    count += len(findings)
        
        return count
    
    def normalize_findings(
        self,
        scoutsuite_data: Dict[str, Any],
        run_id: str
    ) -> List[Finding]:
        """Normalize ScoutSuite findings to AutoPurple format."""
        findings = []
        services = scoutsuite_data.get('services', {})
        
        for service_name, service_data in services.items():
            if isinstance(service_data, dict):
                for resource_type, resources in service_data.items():
                    if isinstance(resources, dict):
                        for resource_id, resource_data in resources.items():
                            if isinstance(resource_data, dict):
                                resource_findings = resource_data.get('findings', [])
                                if isinstance(resource_findings, list):
                                    for finding_data in resource_findings:
                                        finding = self._create_finding(
                                            finding_data,
                                            service_name,
                                            resource_type,
                                            resource_id,
                                            run_id
                                        )
                                        if finding:
                                            findings.append(finding)
        
        logger.info(
            "Normalized ScoutSuite findings",
            total_findings=len(findings),
            run_id=run_id
        )
        
        return findings
    
    def _create_finding(
        self,
        finding_data: Dict[str, Any],
        service: str,
        resource_type: str,
        resource_id: str,
        run_id: str
    ) -> Optional[Finding]:
        """Create a Finding object from ScoutSuite finding data."""
        try:
            # Extract finding details
            title = finding_data.get('title', 'Unknown finding')
            description = finding_data.get('description', '')
            severity = self._normalize_severity(finding_data.get('level', 'info'))
            
            # Create evidence object
            evidence = {
                'title': title,
                'description': description,
                'service': service,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'scoutsuite_data': finding_data
            }
            
            # Generate unique finding ID
            finding_id = f"finding_{uuid.uuid4().hex}"
            
            return Finding(
                id=finding_id,
                run_id=run_id,
                source='scoutsuite',
                service=service,
                resource_id=resource_id,
                title=title,
                severity=severity,
                evidence=evidence
            )
            
        except Exception as e:
            logger.error(
                "Failed to create finding from ScoutSuite data",
                error=str(e),
                finding_data=finding_data
            )
            return None
    
    def _normalize_severity(self, scoutsuite_level: str) -> Severity:
        """Normalize ScoutSuite severity levels to AutoPurple format."""
        severity_map = {
            'danger': 'critical',
            'warning': 'high',
            'info': 'medium',
            'success': 'low'
        }
        
        return severity_map.get(scoutsuite_level.lower(), 'medium')
    
    async def health_check(self) -> bool:
        """Check if ScoutSuite is available and working."""
        try:
            # Check if ScoutSuite module is available
            if self.scoutsuite_path.startswith("python -m"):
                result = await anyio.to_thread.run_sync(
                    subprocess.run,
                    ["python", "-m", "ScoutSuite", "--help"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            else:
                result = await anyio.to_thread.run_sync(
                    subprocess.run,
                    ["python", self.scoutsuite_path, "--help"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error("ScoutSuite health check failed", error=str(e))
            return False

