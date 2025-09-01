# AutoPurple

AI-driven AWS security automation system that extends **ScoutSuite** (discovery) and **Pacu** (exploit validation), and uses **Claude** for orchestration/analysis plus **AWS MCP Servers** for **all** remediation.

## 🎯 Mission

AutoPurple automates the complete AWS security assessment and remediation pipeline:

```
ScoutSuite Discovery → Claude Analysis → Pacu Validation → Claude Planning → MCP Remediation → Validation
```

## 🏗️ Architecture

### Core Principles

1. **Extension over replacement**: Reuse and extend ScoutSuite/Pacu; do not reimplement their core logic
2. **Remediation only after validation**: Never remediate unless Pacu confirms exploitability with evidence
3. **MCP-only infra changes**: All AWS changes are executed through AWS MCP servers
4. **Security-first**: Respect existing security mechanisms; least-privilege IAM; audit everything
5. **Async Python 3.11+**: Prefer `asyncio`/`anyio`, structured concurrency, timeouts, and robust error handling

### Components

- **ScoutSuite Adapter**: AWS security discovery and findings normalization
- **Pacu Adapter**: Exploit validation using Pacu's SQLite session
- **MCP Clients**: AWS CCAPI, CloudFormation, and Documentation MCP servers
- **Claude Planner**: AI-driven analysis and remediation planning
- **Pipeline Orchestrator**: Async DAG for the complete workflow
- **Post-Remediation Validator**: Confirmation of successful fixes

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- AWS credentials configured
- ScoutSuite installed
- Pacu installed
- MCP servers running (optional)

### Installation

```bash
# Clone the repository
git clone https://github.com/autopurple/autopurple.git
cd autopurple

# Install dependencies
pip install -e .

# Install development dependencies
pip install -e ".[dev]"
```

### Configuration

Create a `.env` file:

```bash
# Environment
AUTOPURPLE_ENV=dev

# AWS Configuration
AWS_PROFILE=default
AWS_REGION=us-east-1

# MCP Server Endpoints (optional)
MCP_ENDPOINT_CCAPI=http://localhost:8080
MCP_ENDPOINT_CFN=http://localhost:8081
MCP_ENDPOINT_DOCS=http://localhost:8082

# AI Configuration (optional)
CLAUDE_API_KEY=your_claude_api_key

# Database
AUTOPURPLE_DB_PATH=~/.autopurple/db.sqlite
```

### Usage

```bash
# Run the complete pipeline
autopurple run --profile my-aws-profile --region us-west-2 --max-findings 20

# Run in dry-run mode (default)
autopurple run --dry-run

# Run discovery only
autopurple discover --output findings.json

# Run validation only
autopurple validate findings.json

# Check system health
autopurple health

# Show recent runs
autopurple status
```

## 📊 Database Schema

AutoPurple uses SQLite with the following schema (compatible with Pacu):

```sql
-- AutoPurple runs table
CREATE TABLE ap_runs (
    id TEXT PRIMARY KEY,
    started_at TIMESTAMP NOT NULL,
    ended_at TIMESTAMP,
    aws_account TEXT,
    aws_region TEXT,
    status TEXT CHECK(status IN ('started','validated','remediated','failed')) NOT NULL,
    notes TEXT
);

-- AutoPurple findings table
CREATE TABLE ap_findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES ap_runs(id) ON DELETE CASCADE,
    source TEXT CHECK(source IN ('scoutsuite')) NOT NULL,
    service TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('low','medium','high','critical')) NOT NULL,
    evidence JSON NOT NULL,
    status TEXT CHECK(status IN ('new','validated','dismissed','remediated')) NOT NULL DEFAULT 'new'
);

-- AutoPurple validations table
CREATE TABLE ap_validations (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES ap_findings(id) ON DELETE CASCADE,
    tool TEXT CHECK(tool IN ('pacu')) NOT NULL,
    module TEXT NOT NULL,
    executed_at TIMESTAMP NOT NULL,
    result TEXT CHECK(result IN ('exploitable','not_exploitable','error')) NOT NULL,
    evidence JSON NOT NULL
);

-- AutoPurple remediations table
CREATE TABLE ap_remediations (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES ap_findings(id) ON DELETE CASCADE,
    planned_change JSON NOT NULL,
    mcp_server TEXT NOT NULL,
    mcp_call JSON NOT NULL,
    executed_at TIMESTAMP,
    status TEXT CHECK(status IN ('planned','executed','rolled_back','failed')) NOT NULL,
    audit_ref TEXT
);
```

## 🔧 Development

### Project Structure

```
autopurple/
├── __init__.py
├── config.py              # Configuration management
├── logging.py             # Structured logging
├── db/
│   ├── __init__.py
│   ├── connection.py      # Database connection
│   └── schema.sql         # Database schema
├── models/
│   ├── __init__.py
│   ├── findings.py        # Finding data models
│   ├── remediation.py    # Remediation data models
│   ├── runs.py           # Run data models
│   └── validations.py    # Validation data models
├── adapters/
│   ├── __init__.py
│   ├── scoutsuite_adapter.py  # ScoutSuite integration
│   ├── pacu_adapter.py        # Pacu integration
│   └── mcp/
│       ├── __init__.py
│       ├── ccapi_client.py    # AWS CCAPI MCP client
│       ├── cfn_client.py       # AWS CloudFormation MCP client
│       └── docs_client.py     # AWS Documentation MCP client
├── orchestrator/
│   ├── __init__.py
│   ├── pipeline.py       # Main pipeline orchestrator
│   ├── planner.py        # Claude planning
│   └── validators.py     # Post-remediation validation
├── cli/
│   ├── __init__.py
│   └── main.py           # CLI interface
└── tests/
    ├── unit/
    └── integration/
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=autopurple

# Run specific test file
pytest tests/unit/test_findings.py

# Run integration tests
pytest tests/integration/
```

### Code Quality

```bash
# Run linting
ruff check .

# Run type checking
mypy autopurple/

# Run formatting
black autopurple/
```

## 🔒 Security Considerations

### Credential Management

- Use AWS profiles and STS tokens
- MFA required for AWS operations (configurable)
- Credentials stored in memory only
- Support for role assumption and chaining

### Least Privilege

- Generate example IAM policies for MCP operations
- Validate all MCP plans against allowlist
- Audit trail for every automated action

### Safety Features

- Dry-run mode enabled by default
- Explicit confirmation required for actual changes
- Rollback capabilities for all remediations
- Comprehensive logging and audit trails

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

### Development Guidelines

- Follow the existing code style
- Add type hints to all functions
- Write comprehensive docstrings
- Include tests for new functionality
- Update documentation as needed

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - AWS security auditing
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework
- [AWS MCP Servers](https://awslabs.github.io/mcp/servers/) - Model Context Protocol
- [Claude](https://anthropic.com/claude) - AI assistant for analysis and planning

## 📞 Support

- Issues: [GitHub Issues](https://github.com/autopurple/autopurple/issues)
- Documentation: [Read the Docs](https://autopurple.readthedocs.io)
- Discussions: [GitHub Discussions](https://github.com/autopurple/autopurple/discussions)

