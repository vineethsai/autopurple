# AutoPurple Installation Guide

## Quick Installation

### Prerequisites

- Python 3.11 or higher
- pip or uv package manager
- Git

### Step 1: Clone the Repository

```bash
git clone https://github.com/autopurple/autopurple.git
cd autopurple
```

### Step 2: Install Dependencies

Using pip:
```bash
pip install -e .
```

Using uv (recommended):
```bash
uv sync
```

For development:
```bash
pip install -e ".[dev]"
# or
uv sync --extra dev
```

### Step 3: Configure Environment

Copy the example environment file:
```bash
cp env.example .env
```

Edit `.env` with your configuration:
```bash
# Required: AWS credentials
AWS_PROFILE=your-aws-profile
AWS_REGION=us-east-1

# Optional: MCP server endpoints
MCP_ENDPOINT_CCAPI=http://localhost:8080
MCP_ENDPOINT_CFN=http://localhost:8081
MCP_ENDPOINT_DOCS=http://localhost:8082

# Optional: AI API keys
CLAUDE_API_KEY=your-claude-api-key
```

### Step 4: Install External Tools

#### ScoutSuite
```bash
# Option 1: Using pip
pip install scoutsuite

# Option 2: From source
git clone https://github.com/nccgroup/ScoutSuite.git
cd ScoutSuite
pip install -r requirements.txt
```

#### Pacu
```bash
# Option 1: Using pip
pip install pacu

# Option 2: From source
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu
pip install -r requirements.txt
```

### Step 5: Verify Installation

```bash
# Check if AutoPurple can be imported
python3 -c "import autopurple; print('✓ AutoPurple imported successfully')"

# Check CLI
autopurple --help

# Check health
autopurple health
```

## Development Setup

### Install Development Dependencies

```bash
pip install -e ".[dev]"
```

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=autopurple

# Run specific test
pytest tests/unit/test_findings.py
```

### Code Quality

```bash
# Linting
ruff check .

# Type checking
mypy autopurple/

# Formatting
black autopurple/
```

## Troubleshooting

### Common Issues

1. **ImportError: No module named 'structlog'**
   - Solution: Install dependencies with `pip install -e .`

2. **ScoutSuite not found**
   - Solution: Install ScoutSuite or set `SCOUTSUITE_PATH` in `.env`

3. **Pacu not found**
   - Solution: Install Pacu or set `PACU_PATH` in `.env`

4. **Database errors**
   - Solution: Ensure the database directory exists: `mkdir -p ~/.autopurple`

### Getting Help

- Check the [README.md](README.md) for detailed documentation
- Open an issue on GitHub for bugs
- Join discussions for questions and support

## Next Steps

After installation:

1. Configure your AWS credentials
2. Set up MCP servers (optional)
3. Configure AI API keys (optional)
4. Run a test scan: `autopurple run --dry-run`
5. Review the [README.md](README.md) for usage examples

