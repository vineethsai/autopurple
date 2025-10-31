"""ScoutSuite adapter for AWS security discovery."""

import asyncio
import json
import os
import subprocess
import sys
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
    
    def __init__(self, scoutsuite_path: Optional[str] = None, allow_missing: bool = False):
        """Initialize the ScoutSuite adapter."""
        self.scoutsuite_path = scoutsuite_path or self._find_scoutsuite()
        self.settings = get_settings()
        self.allow_missing = allow_missing
        
        if not self.scoutsuite_path and not allow_missing:
            raise ValueError("ScoutSuite not found. Please install ScoutSuite or provide path.")
        
        if not self.scoutsuite_path:
            logger.warning("ScoutSuite not found - will use mock data")
    
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
        """Run ScoutSuite discovery on AWS account using programmatic API."""
        timeout = timeout or self.settings.scoutsuite_timeout
        
        # Try using ScoutSuite programmatic API
        try:
            from ScoutSuite.core.processingengine import ProcessingEngine
            from ScoutSuite.providers.aws.provider import AWSProvider
            from ScoutSuite.providers.aws.utils import get_available_regions
            
            logger.info("Using ScoutSuite programmatic API")
            
            # Get regions to scan
            regions = [aws_region] if aws_region else ['us-east-1']
            
            # Create AWS provider
            provider = AWSProvider(profile_name=aws_profile)
            
            # Set credentials if provided via environment
            if os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
                import boto3
                from ScoutSuite.providers.aws.utils import manage_dictionary
                
                # Configure provider with access keys
                session = boto3.Session(
                    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                    region_name=regions[0]
                )
                provider.session = session
                provider._set_provider_client_credentials()
            
            print("=" * 80)
            print("SCOUTSUITE DISCOVERY (Programmatic API)")
            print("=" * 80)
            print(f"Regions: {regions}")
            print("Starting scan (this may take several minutes)...")
            print()
            
            # Run discovery in thread
            def run_scoutsuite_sync():
                # Fetch data from AWS
                provider.fetch(regions=regions)
                
                # Process the data
                processing_engine = ProcessingEngine()
                processing_engine.run(provider)
                
                # Get results as dictionary
                return provider.finalize()
            
            scoutsuite_data = await anyio.to_thread.run_sync(
                run_scoutsuite_sync,
                timeout
            )
            
            logger.info(f"ScoutSuite discovery completed with {len(scoutsuite_data.get('services', {}))} services")
            
            print("=" * 80)
            print("SCOUTSUITE DISCOVERY COMPLETE")
            print("=" * 80)
            print(f"Services scanned: {len(scoutsuite_data.get('services', {}))}")
            print()
            
            return scoutsuite_data
            
        except ImportError:
            # Fallback to direct AWS API discovery
            logger.warning("ScoutSuite programmatic API not available, using direct AWS API")
            return await self._run_direct_aws_discovery(aws_region)
        except Exception as e:
            logger.error(f"ScoutSuite programmatic API failed: {e}, falling back to direct AWS API")
            return await self._run_direct_aws_discovery(aws_region)
    
    async def _run_direct_aws_discovery(self, aws_region: Optional[str] = None) -> Dict[str, Any]:
        """Run direct AWS API discovery as fallback."""
        import boto3
        from datetime import datetime
        
        logger.info("Using direct AWS API for discovery")
        
        # If specific region provided, use it; otherwise scan all regions
        target_region = aws_region or self.settings.aws_region
        
        print("=" * 80)
        print("AWS DIRECT API DISCOVERY")
        print("=" * 80)
        if target_region:
            print(f"Region: {target_region}")
        else:
            print("Scanning ALL regions (no specific region specified)")
        print("Querying AWS services directly...")
        print()
        
        findings_data = {
            "services": {},
            "account_id": None,
            "region": target_region or "all",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Get account ID
        try:
            sts = boto3.client('sts',
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                region_name='us-east-1'  # STS is global, but need to specify region
            )
            identity = sts.get_caller_identity()
            findings_data['account_id'] = identity['Account']
            print(f"Account ID: {identity['Account']}")
        except Exception as e:
            logger.error(f"Failed to get account ID: {e}")
            return findings_data
        
        # Get list of regions to scan
        ec2_base = boto3.client('ec2',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            region_name='us-east-1'
        )
        
        if target_region:
            regions_to_scan = [target_region]
        else:
            # Get all available regions
            regions_to_scan = [r['RegionName'] for r in ec2_base.describe_regions()['Regions']]
        
        # Check EC2 Security Groups across all specified regions
        print(f"Scanning EC2 Security Groups in {len(regions_to_scan)} region(s)...")
        total_sgs = 0
        ec2_findings_list = []
        
        try:
            for region in regions_to_scan:
                try:
                    ec2 = boto3.client('ec2', region_name=region,
                        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
                    )
                    sgs = ec2.describe_security_groups()['SecurityGroups']
                    total_sgs += len(sgs)
                    print(f"  {region}: {len(sgs)} security groups")
                    
                    for sg in sgs:
                        sg_id = sg['GroupId']
                        for perm in sg.get('IpPermissions', []):
                            for ip_range in perm.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    from_port = perm.get('FromPort', 0)
                                    to_port = perm.get('ToPort', 65535)
                                    protocol = perm.get('IpProtocol', '-1')
                                    
                                    # Only create finding if it's actually a security issue
                                    # Check if it's all ports (0-65535) or common dangerous ports
                                    is_critical = (
                                        (from_port == -1 or (from_port == 0 and to_port == 65535)) or  # All ports
                                        (from_port <= 22 and to_port >= 22) or  # SSH
                                        (from_port <= 3389 and to_port >= 3389) or  # RDP
                                        (from_port <= 3306 and to_port >= 3306)  # MySQL
                                    )
                                    
                                    finding = {
                                        'title': 'Security Group Opens Ports to Internet' if is_critical else 'Security Group Has Public Access',
                                        'description': f"Security group {sg_id} allows access from 0.0.0.0/0 on {protocol} ports {from_port}-{to_port}",
                                        'level': 'danger' if is_critical else 'warning',
                                        'evidence': {
                                            'security_group_id': sg_id,
                                            'arn': sg.get('GroupArn', f'arn:aws:ec2:{region}:{findings_data["account_id"]}:security-group/{sg_id}'),
                                            'region': region,  # Store the actual region where SG was found
                                            'vpc_id': sg.get('VpcId', ''),
                                            'description': sg.get('Description', ''),
                                            'cidr': '0.0.0.0/0',
                                            'ports': f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                                            'protocol': protocol
                                        }
                                    }
                                    ec2_findings_list.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to scan {region}: {e}")
                    print(f"  {region}: Error - {e}")
                    continue
            
            print(f"  Total security groups scanned: {total_sgs}")
            
            if ec2_findings_list:
                # Group by security group
                sg_findings = {}
                for finding in ec2_findings_list:
                    sg_id = finding['evidence']['security_group_id']
                    if sg_id not in sg_findings:
                        sg_findings[sg_id] = []
                    sg_findings[sg_id].append(finding)
                
                findings_data['services']['ec2'] = {
                    'security_group': {
                        sg_id: {'findings': findings}
                        for sg_id, findings in sg_findings.items()
                    }
                }
                print(f"  ⚠️  Found {len(ec2_findings_list)} security group vulnerabilities")
        except Exception as e:
            logger.warning(f"EC2 discovery failed: {e}")
            print(f"  ⚠️  EC2 discovery error: {e}")
        
        # Check S3 Buckets
        print("Scanning S3 Buckets...")
        try:
            s3 = boto3.client('s3',
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
            )
            buckets = s3.list_buckets()['Buckets']
            print(f"  Found {len(buckets)} buckets")
            
            s3_findings_list = []
            for bucket in buckets[:10]:  # Limit to first 10 for speed
                bucket_name = bucket['Name']
                try:
                    # Check bucket policy
                    try:
                        policy = s3.get_bucket_policy(Bucket=bucket_name)
                        policy_json = json.loads(policy['Policy'])
                        # Check if policy allows public access
                        for statement in policy_json.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                principal = statement.get('Principal', {})
                                if '*' in str(principal) or 'AWS' not in str(principal):
                                    s3_findings_list.append({
                                        'title': 'S3 Bucket Publicly Accessible',
                                        'description': f"Bucket {bucket_name} has a policy allowing public access",
                                        'level': 'danger',
                                        'evidence': {
                                            'bucket_name': bucket_name,
                                            'public_access': True,
                                            'policy': policy_json
                                        }
                                    })
                    except s3.exceptions.from_code('NoSuchBucketPolicy'):
                        pass
                    
                    # Check ACL
                    try:
                        acl = s3.get_bucket_acl(Bucket=bucket_name)
                        for grant in acl.get('Grants', []):
                            grantee = grant.get('Grantee', {})
                            if grantee.get('Type') == 'Group' and 'AllUsers' in str(grantee.get('URI', '')):
                                s3_findings_list.append({
                                    'title': 'S3 Bucket Publicly Accessible via ACL',
                                    'description': f"Bucket {bucket_name} has public read access via ACL",
                                    'level': 'danger',
                                    'evidence': {
                                        'bucket_name': bucket_name,
                                        'public_access': True,
                                        'acl': str(acl)
                                    }
                                })
                    except Exception:
                        pass
                except Exception as e:
                    logger.debug(f"Error checking bucket {bucket_name}: {e}")
                    continue
            
            if s3_findings_list:
                if 's3' not in findings_data['services']:
                    findings_data['services']['s3'] = {}
                findings_data['services']['s3']['bucket'] = {
                    finding['evidence']['bucket_name']: {'findings': [finding]}
                    for finding in s3_findings_list
                }
                print(f"  ⚠️  Found {len(s3_findings_list)} S3 bucket vulnerabilities")
        except Exception as e:
            logger.warning(f"S3 discovery failed: {e}")
            print(f"  ⚠️  S3 discovery error: {e}")
        
        # Check IAM Users (overly permissive)
        print("Scanning IAM Users...")
        try:
            iam = boto3.client('iam',
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
            )
            users = iam.list_users()['Users']
            print(f"  Found {len(users)} IAM users")
            
            # Note: Full IAM policy analysis would take longer
            # For now, just note we found users
        except Exception as e:
            logger.warning(f"IAM discovery failed: {e}")
        
        print()
        print("=" * 80)
        print("AWS DIRECT DISCOVERY COMPLETE")
        print("=" * 80)
        total = self._count_findings(findings_data)
        print(f"Total findings discovered: {total}")
        print()
        
        return findings_data
    
    async def _run_discovery_cli(
        self,
        aws_profile: Optional[str] = None,
        aws_region: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """Run ScoutSuite discovery using CLI (fallback method)."""
        timeout = timeout or self.settings.scoutsuite_timeout
        
        # Build ScoutSuite command
        report_name = f"autopurple_{uuid.uuid4().hex[:8]}"
        report_dir = "/tmp/scoutsuite_reports"
        
        # Ensure report directory exists
        Path(report_dir).mkdir(parents=True, exist_ok=True)
        
        # Use ScoutSuite via Python module
        cmd = [
            sys.executable, "-m", "ScoutSuite",
            "aws",
            "--report-dir", report_dir,
            "--report-name", report_name,
            "--no-browser"
        ]
        
        # Use access keys if environment variables are set, otherwise use profile
        if os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
            cmd.extend([
                "--access-keys",
                "--access-key-id", os.environ.get('AWS_ACCESS_KEY_ID'),
                "--secret-access-key", os.environ.get('AWS_SECRET_ACCESS_KEY')
            ])
        elif aws_profile:
            cmd.extend(["--profile", aws_profile])
        
        if aws_region:
            cmd.extend(["--regions", aws_region])
        
        logger.info(
            "Starting ScoutSuite discovery (CLI)",
            cmd=" ".join(cmd),
            timeout=timeout
        )
        
        try:
            # Run ScoutSuite in a thread to avoid blocking
            result = await anyio.to_thread.run_sync(
                self._run_scoutsuite_subprocess,
                cmd,
                timeout
            )
            
            # Print output for debugging
            if result.stdout:
                print("=" * 80)
                print("SCOUTSUITE STDOUT")
                print("=" * 80)
                print(result.stdout[-2000:])  # Last 2000 chars
                print("=" * 80)
            
            if result.stderr:
                print("=" * 80)
                print("SCOUTSUITE STDERR")
                print("=" * 80)
                print(result.stderr[-2000:])  # Last 2000 chars
                print("=" * 80)
            
            if result.returncode != 0:
                error_msg = result.stderr[-1000:] or result.stdout[-1000:]
                raise RuntimeError(f"ScoutSuite failed (return code {result.returncode}): {error_msg}")
            
            # Wait for file system sync
            await asyncio.sleep(2)
            
            # Find report files - try all patterns
            report_files = []
            patterns = [
                f"scoutsuite-report-*-{report_name}.json",
                "scoutsuite-report-*.json",
                f"{report_name}.json",
                "*.json"
            ]
            
            for pattern in patterns:
                report_files.extend(list(Path(report_dir).glob(pattern)))
                if report_files:
                    break
            
            # Also check subdirectories
            if not report_files:
                for subdir in Path(report_dir).iterdir():
                    if subdir.is_dir():
                        report_files.extend(list(subdir.glob("*.json")))
            
            if not report_files:
                # List all directory contents
                dir_contents = []
                if Path(report_dir).exists():
                    for item in Path(report_dir).rglob("*"):
                        dir_contents.append(str(item.relative_to(Path(report_dir))))
                
                dir_list = "\n".join(dir_contents[:20]) or "empty"
                raise RuntimeError(
                    f"ScoutSuite completed but no JSON report found in {report_dir}.\n"
                    f"Directory structure:\n{dir_list}\n\n"
                    f"ScoutSuite stdout (last 500 chars): {result.stdout[-500:]}\n"
                    f"ScoutSuite stderr (last 500 chars): {result.stderr[-500:]}"
                )
            
            # Use the most recent report file
            report_file = max(report_files, key=lambda p: p.stat().st_mtime)
            
            logger.info(f"Loading ScoutSuite report from {report_file}")
            
            # Load and parse the JSON report
            with open(report_file, 'r') as f:
                scoutsuite_data = json.load(f)
            
            logger.info(f"Loaded ScoutSuite report with {len(scoutsuite_data.get('services', {}))} services")
            return scoutsuite_data
            
        except Exception as e:
            logger.error("ScoutSuite discovery failed", error=str(e))
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
        env = os.environ.copy()
        
        # Add AWS environment variables if configured
        if self.settings.aws_profile:
            env["AWS_PROFILE"] = self.settings.aws_profile
        if self.settings.aws_region:
            env["AWS_DEFAULT_REGION"] = self.settings.aws_region
        
        return env
    
    def _generate_mock_findings(self) -> Dict[str, Any]:
        """Generate mock findings for testing purposes (deprecated - use real ScoutSuite)."""
        raise RuntimeError("Mock findings disabled. Please use real ScoutSuite for discovery.")
    
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
    
    def _run_health_check_subprocess(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Run health check subprocess."""
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
    
    async def health_check(self) -> bool:
        """Check if ScoutSuite is available and working."""
        try:
            # Use ScoutSuite via Python module
            cmd = [sys.executable, "-m", "ScoutSuite", "--help"]
            
            result = await anyio.to_thread.run_sync(
                self._run_health_check_subprocess,
                cmd
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error("ScoutSuite health check failed", error=str(e))
            return False

