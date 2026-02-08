# SecureChain VEXGen

[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Lint & Test](https://github.com/securechaindev/securechain-vexgen/actions/workflows/lint-test.yml/badge.svg)]()
[![GHCR](https://img.shields.io/badge/GHCR-securechain--vexgen-blue?logo=docker)](https://github.com/orgs/securechaindev/packages/container/package/securechain-vexgen)

## What is VEXGen?

**VEXGen** is an automated tool for generating **VEX (Vulnerability Exploitability eXchange)** and **TIX (Threat Intelligence eXchange)** documents from GitHub repositories.

### Key Features

- 🔍 **Automatic SBOM Discovery** - Finds and processes Software Bill of Materials files
- 🧠 **Smart Code Analysis** - Multi-language analyzer detects actual component usage
- 📊 **Vulnerability Assessment** - Determines exploitability using package affected artefacts
- 📦 **VEX/TIX Generation** - Creates standards-compliant security documents

## Development Requirements

1. **[Docker](https://www.docker.com/)** - Container runtime
2. **[Docker Compose](https://docs.docker.com/compose/)** - Multi-container orchestration
3. **[MongoDB Compass](https://www.mongodb.com/products/compass)** (optional) - MongoDB GUI
4. **[Neo4j Browser](http://localhost:7474)** - Graph database visualization (runs on container)
5. **Python 3.14+** - For local development

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/securechaindev/securechain-vexgen.git
cd securechain-vexgen
```

### 2. Configure Environment Variables
Create a `.env` file from `.env.template`:
```bash
cp .env.template .env
```

Edit `.env` with your configuration:

#### Get API Keys
- **GitHub**: [Personal Access Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- **JWT Secret**: Generate with `openssl rand -base64 32`

### 3. Setup Docker Network
```bash
docker network create securechain
```

### 4. Seed Databases
Download [database dumps](https://doi.org/10.5281/zenodo.16739080) from **Zenodo**, unzip, and run:
```bash
docker compose up --build
```

The MongoDB and Neo4j containers will be seeded automatically.

### 5. Start the Application
```bash
docker compose -f dev/docker-compose.yml up --build
```

### 6. Access the API
- **VEXGen API**: [http://localhost:8002](http://localhost:8002)
- **API Docs**: [http://localhost:8002/docs](http://localhost:8002/docs)
- **Auth API**: [http://localhost:8001/docs](http://localhost:8001/docs)
- **Neo4j Browser**: [http://localhost:7474](http://localhost:7474)
- **MongoDB**: `mongodb://localhost:27017`

## Python Environment
The project uses Python 3.14 and **uv** as the package manager for faster and more reliable dependency management.

### Setting up the development environment with uv

1. **Install uv** (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Activate the virtual environment** (uv creates it automatically):
   ```bash
   uv venv
   source .venv/bin/activate
   ```

2. **Install dependencies**:
   ```bash
   uv sync
   ```

## Testing

The project uses pytest with coverage tracking. Current coverage: **84%** (407 tests passing).

```bash
# Install test dependencies
uv sync --extra test

# Run all tests
uv run pytest

# Run tests with coverage report
uv run pytest --cov=app --cov-report=term-missing --cov-report=html

# Run specific test file
uv run pytest tests/unit/controllers/test_graph_controller.py -v

# Run only unit tests
uv run pytest tests/unit/ -v
```

## Code Quality
```bash
# Install linter
uv sync --extra dev

# Linting
uv run ruff check app/

# Formatting
uv run ruff format app/
```

## Contributing

Pull requests are welcome! For major changes, please open an issue first.

## License

[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html)
