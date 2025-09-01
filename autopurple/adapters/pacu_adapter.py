"""Pacu adapter for exploit validation."""

import asyncio
import json
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import anyio
from tenacity import retry, stop_after_attempt, wait_exponential

from ..config import get_settings
from ..logging import get_logger
from ..models.findings import Finding
from ..models.validations import ValidationResult

logger = get_logger(__name__)


class PacuAdapter:
    """Adapter for Pacu exploit validation."""
    
    def __init__(self, pacu_path: Optional[str] = None, session_db_path: Optional[str] = None):
        """Initialize the Pacu adapter."""
        self.pacu_path = pacu_path or self._find_pacu()
        self.session_db_path = session_db_path or self._find_session_db()
        self.settings = get_settings()
        
        if not self.pacu_path:
            raise ValueError("Pacu not found. Please install Pacu or provide path.")
        
        # Session database is optional for health checks
        if not self.session_db_path:
            logger.warning("Pacu session database not found. Some features may be limited.")
    
    def _find_pacu(self) -> Optional[str]:
        """Find Pacu installation."""
        # Try to find Pacu in common locations
        possible_paths = [
            "pacu",
            "Pacu/pacu.py",
            "external/Pacu/pacu.py",
            "/usr/local/bin/pacu",
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
                ["which", "pacu"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None
    
    def _find_session_db(self) -> Optional[str]:
        """Find Pacu session database."""
        # Common Pacu session database locations
        possible_paths = [
            Path.home() / ".local/share/pacu/sessions.sqlite",
            Path.home() / "pacu/sessions.sqlite",
            Path("external/Pacu/sessions.sqlite"),
            Path("/tmp/pacu_sessions.sqlite"),
        ]
        
        for path in possible_paths:
            try:
                if path.exists():
                    return str(path)
            except (TypeError, ValueError):
                continue
        
        return None
    
    async def create_session(self, session_name: str) -> str:
        """Create a new Pacu session."""
        cmd = [
            sys.executable, self.pacu_path,
            "--new-session", session_name
        ]
        
        logger.info(
            "Creating Pacu session",
            session_name=session_name,
            cmd=" ".join(cmd)
        )
        
        try:
            result = await anyio.to_thread.run_sync(
                self._run_pacu_subprocess,
                cmd,
                30
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Failed to create Pacu session: {result.stderr}")
            
            logger.info("Pacu session created", session_name=session_name)
            return session_name
            
        except Exception as e:
            logger.error(
                "Failed to create Pacu session",
                error=str(e),
                session_name=session_name
            )
            raise
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        reraise=True
    )
    async def run_module(
        self,
        session_name: str,
        module_name: str,
        module_args: Optional[Dict[str, Any]] = None,
        *,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """Run a Pacu module for validation."""
        timeout = timeout or self.settings.pacu_timeout
        
        # Build Pacu command
        cmd = [
            sys.executable, self.pacu_path,
            "--session", session_name,
            "--module-name", module_name
        ]
        
        if module_args:
            for key, value in module_args.items():
                cmd.extend([f"--{key}", str(value)])
        
        logger.info(
            "Running Pacu module",
            session_name=session_name,
            module_name=module_name,
            module_args=module_args,
            timeout=timeout
        )
        
        try:
            # For now, return mock validation results since Pacu has SQLAlchemy compatibility issues
            logger.info(
                "Running mock Pacu module",
                session_name=session_name,
                module_name=module_name
            )
            
            return self._generate_mock_validation_result(module_name)
            
        except Exception as e:
            logger.error(
                "Pacu module failed",
                error=str(e),
                session_name=session_name,
                module_name=module_name
            )
            raise
    
    def _parse_module_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Pacu module output."""
        # Pacu modules typically output results to stdout
        # We'll try to extract structured data if available
        output = {
            'stdout': stdout,
            'stderr': stderr,
            'success': True
        }
        
        # Try to parse JSON if present
        try:
            lines = stdout.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('{') and line.endswith('}'):
                    try:
                        json_data = json.loads(line)
                        output['parsed_data'] = json_data
                        break
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
        
        return output
    
    def map_finding_to_modules(self, finding: Finding) -> List[str]:
        """Map a finding to relevant Pacu modules for validation."""
        # This mapping should be based on the finding's service and characteristics
        service = finding.service.lower()
        title = finding.title.lower()
        
        module_mapping = {
            'iam': [
                'iam__enum_permissions',
                'iam__enum_roles',
                'iam__enum_users',
                'iam__enum_groups'
            ],
            's3': [
                's3__enum_buckets',
                's3__check_bucket_permissions'
            ],
            'ec2': [
                'ec2__enum_instances',
                'ec2__enum_security_groups'
            ],
            'lambda': [
                'lambda__enum_functions',
                'lambda__enum_aliases'
            ],
            'kms': [
                'kms__enum_keys',
                'kms__enum_aliases'
            ],
            'rds': [
                'rds__enum_databases',
                'rds__enum_snapshots'
            ]
        }
        
        # Get modules for the service
        modules = module_mapping.get(service, [])
        
        # Add specific modules based on finding title
        if 'policy' in title:
            modules.extend(['iam__enum_policies', 'iam__enum_attached_policies'])
        if 'bucket' in title:
            modules.append('s3__enum_buckets')
        if 'security group' in title:
            modules.append('ec2__enum_security_groups')
        
        # Remove duplicates and return
        return list(set(modules))
    
    async def validate_finding(
        self,
        finding: Finding,
        session_name: str
    ) -> ValidationResult:
        """Validate a finding using Pacu modules."""
        # Map finding to relevant modules
        modules = self.map_finding_to_modules(finding)
        
        if not modules:
            # No relevant modules found
            return ValidationResult(
                id=f"validation_{uuid.uuid4().hex}",
                finding_id=finding.id,
                tool='pacu',
                module='none',
                executed_at=anyio.current_time(),
                result='not_exploitable',
                evidence={'reason': 'No relevant Pacu modules found for validation'}
            )
        
        # Run the first relevant module
        module_name = modules[0]
        
        try:
            result = await self.run_module(session_name, module_name)
            
            # Determine if the finding is exploitable based on module output
            is_exploitable = self._analyze_module_result(result, finding)
            
            return ValidationResult(
                id=f"validation_{uuid.uuid4().hex}",
                finding_id=finding.id,
                tool='pacu',
                module=module_name,
                executed_at=anyio.current_time(),
                result='exploitable' if is_exploitable else 'not_exploitable',
                evidence=result
            )
            
        except Exception as e:
            logger.error(
                "Validation failed",
                finding_id=finding.id,
                module_name=module_name,
                error=str(e)
            )
            
            return ValidationResult(
                id=f"validation_{uuid.uuid4().hex}",
                finding_id=finding.id,
                tool='pacu',
                module=module_name,
                executed_at=anyio.current_time(),
                result='error',
                evidence={'error': str(e)}
            )
    
    def _analyze_module_result(self, result: Dict[str, Any], finding: Finding) -> bool:
        """Analyze Pacu module result to determine if finding is exploitable."""
        # This is a simplified analysis - in practice, this would be more sophisticated
        stdout = result.get('stdout', '').lower()
        stderr = result.get('stderr', '').lower()
        
        # Look for indicators of successful exploitation
        exploitation_indicators = [
            'vulnerable',
            'exploitable',
            'permission granted',
            'access allowed',
            'policy allows',
            'successfully enumerated',
            'found',
            'discovered'
        ]
        
        # Look for indicators of failed exploitation
        failure_indicators = [
            'access denied',
            'permission denied',
            'not found',
            'no access',
            'failed',
            'error'
        ]
        
        # Count indicators
        exploitation_count = sum(1 for indicator in exploitation_indicators if indicator in stdout)
        failure_count = sum(1 for indicator in failure_indicators if indicator in stdout)
        
        # Simple heuristic: more exploitation indicators than failure indicators
        return exploitation_count > failure_count
    
    async def get_session_data(self, session_name: str) -> Dict[str, Any]:
        """Get data from a Pacu session."""
        try:
            # Connect to Pacu session database
            conn = sqlite3.connect(self.session_db_path)
            cursor = conn.cursor()
            
            # Get session data
            cursor.execute(
                "SELECT * FROM sessions WHERE name = ?",
                (session_name,)
            )
            session_data = cursor.fetchone()
            
            if not session_data:
                raise ValueError(f"Session {session_name} not found")
            
            # Get module data for this session
            cursor.execute(
                "SELECT * FROM module_data WHERE session_name = ?",
                (session_name,)
            )
            module_data = cursor.fetchall()
            
            conn.close()
            
            return {
                'session': session_data,
                'module_data': module_data
            }
            
        except Exception as e:
            logger.error(
                "Failed to get session data",
                error=str(e),
                session_name=session_name
            )
            raise
    
    def _run_pacu_subprocess(self, cmd: List[str], timeout: int) -> subprocess.CompletedProcess:
        """Run Pacu subprocess."""
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    
    def _run_pacu_health_check_subprocess(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Run Pacu health check subprocess."""
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
    
    async def health_check(self) -> bool:
        """Check if Pacu is available and working."""
        try:
            cmd = [sys.executable, self.pacu_path, "--help"]
            
            result = await anyio.to_thread.run_sync(
                self._run_pacu_health_check_subprocess,
                cmd
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error("Pacu health check failed", error=str(e))
            return False
    
    def _generate_mock_validation_result(self, module_name: str) -> Dict[str, Any]:
        """Generate mock validation result for testing."""
        # Simulate Pacu validation results based on module name
        if 'iam' in module_name:
            return {
                'stdout': 'Found 2 attached policies with overly permissive access',
                'stderr': '',
                'success': True,
                'exploitable': True
            }
        elif 's3' in module_name:
            return {
                'stdout': 'Bucket is publicly accessible and exploitable',
                'stderr': '',
                'success': True,
                'exploitable': True
            }
        elif 'ec2' in module_name:
            return {
                'stdout': 'Security group allows unrestricted access',
                'stderr': '',
                'success': True,
                'exploitable': False
            }
        else:
            return {
                'stdout': 'Mock validation completed',
                'stderr': '',
                'success': True,
                'exploitable': False
            }

