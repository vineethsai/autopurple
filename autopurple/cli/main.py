"""Main CLI application for AutoPurple."""

import asyncio
import uuid
from datetime import datetime
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..config import get_settings
from ..db import init_database
from ..logging import get_logger
from ..models.runs import Run
from ..orchestrator.pipeline import AutoPurplePipeline

app = typer.Typer(
    name="autopurple",
    help="AI-driven AWS security automation system",
    add_completion=False
)

console = Console()
logger = get_logger(__name__)


@app.command()
def run(
    profile: Optional[str] = typer.Option(
        None, "--profile", "-p", help="AWS profile to use"
    ),
    region: Optional[str] = typer.Option(
        None, "--region", "-r", help="AWS region to scan"
    ),
    max_findings: int = typer.Option(
        10, "--max-findings", "-m", help="Maximum findings to process"
    ),
    dry_run: bool = typer.Option(
        True, "--dry-run/--no-dry-run", help="Run in dry-run mode (default: True)"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose logging"
    ),
) -> None:
    """Run the complete AutoPurple pipeline."""
    settings = get_settings()
    
    # Override settings with CLI arguments
    if profile:
        settings.aws_profile = profile
    if region:
        settings.aws_region = region
    
    # Set dry-run mode
    settings.dry_run_default = dry_run
    
    # Set log level
    if verbose:
        settings.log_level = "DEBUG"
    
    console.print(f"[bold blue]AutoPurple[/bold blue] - AWS Security Automation")
    console.print(f"Profile: {settings.aws_profile or 'default'}")
    console.print(f"Region: {settings.aws_region}")
    console.print(f"Dry-run: {dry_run}")
    console.print(f"Max findings: {max_findings}")
    console.print()
    
    # Run the pipeline
    asyncio.run(_run_pipeline(settings, max_findings))


@app.command()
def discover(
    profile: Optional[str] = typer.Option(
        None, "--profile", "-p", help="AWS profile to use"
    ),
    region: Optional[str] = typer.Option(
        None, "--region", "-r", help="AWS region to scan"
    ),
    output: str = typer.Option(
        "findings.json", "--output", "-o", help="Output file for findings"
    ),
) -> None:
    """Run ScoutSuite discovery only."""
    settings = get_settings()
    
    if profile:
        settings.aws_profile = profile
    if region:
        settings.aws_region = region
    
    console.print(f"[bold blue]AutoPurple[/bold blue] - Discovery Phase")
    console.print(f"Profile: {settings.aws_profile or 'default'}")
    console.print(f"Region: {settings.aws_region}")
    console.print(f"Output: {output}")
    console.print()
    
    asyncio.run(_run_discovery(settings, output))


@app.command()
def validate(
    findings_file: str = typer.Argument(..., help="Findings file to validate"),
    profile: Optional[str] = typer.Option(
        None, "--profile", "-p", help="AWS profile to use"
    ),
) -> None:
    """Run Pacu validation on findings."""
    settings = get_settings()
    
    if profile:
        settings.aws_profile = profile
    
    console.print(f"[bold blue]AutoPurple[/bold blue] - Validation Phase")
    console.print(f"Findings file: {findings_file}")
    console.print(f"Profile: {settings.aws_profile or 'default'}")
    console.print()
    
    asyncio.run(_run_validation(settings, findings_file))


@app.command()
def status() -> None:
    """Show status of recent runs."""
    console.print(f"[bold blue]AutoPurple[/bold blue] - Status")
    console.print()
    
    asyncio.run(_show_status())


@app.command()
def health() -> None:
    """Check health of all components."""
    console.print(f"[bold blue]AutoPurple[/bold blue] - Health Check")
    console.print()
    
    asyncio.run(_check_health())


async def _run_pipeline(settings, max_findings: int) -> None:
    """Run the complete AutoPurple pipeline."""
    try:
        # Initialize database
        await init_database()
        
        # Create pipeline
        pipeline = AutoPurplePipeline()
        
        # Create run
        run_id = f"run_{uuid.uuid4().hex[:8]}"
        run = Run(
            id=run_id,
            started_at=datetime.utcnow(),
            aws_account=settings.aws_profile,
            aws_region=settings.aws_region
        )
        
        console.print(f"[green]Starting pipeline run: {run_id}[/green]")
        
        # Run pipeline
        result = await pipeline.execute(
            run=run,
            max_findings=max_findings,
            dry_run=settings.dry_run_default
        )
        
        # Display results
        _display_pipeline_results(result)
        
    except Exception as e:
        console.print(f"[red]Pipeline failed: {e}[/red]")
        logger.error("Pipeline execution failed", error=str(e))
        raise typer.Exit(1)


async def _run_discovery(settings, output_file: str) -> None:
    """Run discovery phase only."""
    try:
        from ..adapters.scoutsuite_adapter import ScoutSuiteAdapter
        
        # Initialize ScoutSuite adapter
        scoutsuite = ScoutSuiteAdapter()
        
        console.print("[yellow]Running ScoutSuite discovery...[/yellow]")
        
        # Run discovery
        result = await scoutsuite.run_discovery(
            aws_profile=settings.aws_profile,
            aws_region=settings.aws_region
        )
        
        # Normalize findings
        findings = scoutsuite.normalize_findings(result, "discovery_run")
        
        # Save to file
        import json
        with open(output_file, 'w') as f:
            json.dump([finding.to_dict() for finding in findings], f, indent=2)
        
        console.print(f"[green]Discovery completed! Found {len(findings)} findings.[/green]")
        console.print(f"Results saved to: {output_file}")
        
    except Exception as e:
        console.print(f"[red]Discovery failed: {e}[/red]")
        logger.error("Discovery failed", error=str(e))
        raise typer.Exit(1)


async def _run_validation(settings, findings_file: str) -> None:
    """Run validation phase only."""
    try:
        from ..adapters.pacu_adapter import PacuAdapter
        import json
        
        # Load findings
        with open(findings_file, 'r') as f:
            findings_data = json.load(f)
        
        # Initialize Pacu adapter
        pacu = PacuAdapter()
        
        # Create session
        session_name = f"validation_{uuid.uuid4().hex[:8]}"
        await pacu.create_session(session_name)
        
        console.print(f"[yellow]Created Pacu session: {session_name}[/yellow]")
        console.print(f"[yellow]Validating {len(findings_data)} findings...[/yellow]")
        
        # Validate each finding
        results = []
        for finding_data in findings_data:
            from ..models.findings import Finding
            finding = Finding.from_dict(finding_data)
            
            validation = await pacu.validate_finding(finding, session_name)
            results.append(validation.to_dict())
            
            status_icon = "🟢" if validation.is_exploitable else "🔴"
            console.print(f"{status_icon} {finding.title}: {validation.result}")
        
        # Save results
        output_file = findings_file.replace('.json', '_validated.json')
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        console.print(f"[green]Validation completed! Results saved to: {output_file}[/green]")
        
    except Exception as e:
        console.print(f"[red]Validation failed: {e}[/red]")
        logger.error("Validation failed", error=str(e))
        raise typer.Exit(1)


async def _show_status() -> None:
    """Show status of recent runs."""
    try:
        await init_database()
        
        # This would query the database for recent runs
        # For now, show a placeholder
        table = Table(title="Recent AutoPurple Runs")
        table.add_column("Run ID", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Started", style="blue")
        table.add_column("Duration", style="yellow")
        table.add_column("Findings", style="magenta")
        
        table.add_row(
            "run_abc123",
            "completed",
            "2024-01-15 10:30:00",
            "45m 30s",
            "12"
        )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Failed to show status: {e}[/red]")
        raise typer.Exit(1)


async def _check_health() -> None:
    """Check health of all components."""
    try:
        # Check database
        await init_database()
        console.print("✅ Database: [green]OK[/green]")
        
        # Check ScoutSuite
        from ..adapters.scoutsuite_adapter import ScoutSuiteAdapter
        scoutsuite = ScoutSuiteAdapter()
        if await scoutsuite.health_check():
            console.print("✅ ScoutSuite: [green]OK[/green]")
        else:
            console.print("❌ ScoutSuite: [red]FAILED[/red]")
        
        # Check Pacu
        from ..adapters.pacu_adapter import PacuAdapter
        pacu = PacuAdapter()
        if await pacu.health_check():
            console.print("✅ Pacu: [green]OK[/green]")
        else:
            console.print("❌ Pacu: [red]FAILED[/red]")
        
        # Check MCP servers
        settings = get_settings()
        
        if settings.mcp_endpoint_ccapi:
            from ..adapters.mcp.ccapi_client import CCAPIClient
            ccapi = CCAPIClient()
            try:
                await ccapi.health_check()
                console.print("✅ CCAPI MCP: [green]OK[/green]")
            except Exception:
                console.print("❌ CCAPI MCP: [red]FAILED[/red]")
        
        if settings.mcp_endpoint_cfn:
            from ..adapters.mcp.cfn_client import CloudFormationClient
            cfn = CloudFormationClient()
            try:
                await cfn.health_check()
                console.print("✅ CloudFormation MCP: [green]OK[/green]")
            except Exception:
                console.print("❌ CloudFormation MCP: [red]FAILED[/red]")
        
        if settings.mcp_endpoint_docs:
            from ..adapters.mcp.docs_client import DocsClient
            docs = DocsClient()
            try:
                await docs.health_check()
                console.print("✅ Docs MCP: [green]OK[/green]")
            except Exception:
                console.print("❌ Docs MCP: [red]FAILED[/red]")
        
    except Exception as e:
        console.print(f"[red]Health check failed: {e}[/red]")
        raise typer.Exit(1)


def _display_pipeline_results(result: dict) -> None:
    """Display pipeline results in a nice format."""
    console.print()
    console.print("[bold green]Pipeline Results[/bold green]")
    console.print()
    
    # Summary table
    table = Table(title="Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Findings", str(result.get('total_findings', 0)))
    table.add_row("Validated", str(result.get('validated', 0)))
    table.add_row("Exploitable", str(result.get('exploitable', 0)))
    table.add_row("Remediated", str(result.get('remediated', 0)))
    table.add_row("Duration", result.get('duration', 'N/A'))
    
    console.print(table)
    
    # Findings table
    if result.get('findings'):
        findings_table = Table(title="Findings")
        findings_table.add_column("Service", style="cyan")
        findings_table.add_column("Title", style="white")
        findings_table.add_column("Severity", style="red")
        findings_table.add_column("Status", style="green")
        
        for finding in result['findings']:
            severity_color = {
                'critical': 'red',
                'high': 'yellow',
                'medium': 'blue',
                'low': 'green'
            }.get(finding.get('severity', 'medium'), 'white')
            
            findings_table.add_row(
                finding.get('service', ''),
                finding.get('title', ''),
                f"[{severity_color}]{finding.get('severity', '')}[/{severity_color}]",
                finding.get('status', '')
            )
        
        console.print(findings_table)


if __name__ == "__main__":
    app()

