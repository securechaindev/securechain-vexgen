# 🔒 SecureChain VEXGen

[![Python Version](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.116.1-009688.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## 📋 What is VEXGen?

**VEXGen** is an automated tool for generating **VEX (Vulnerability Exploitability eXchange)** and **TIX (Threat Intelligence eXchange)** documents from GitHub repositories.

### Key Features

- 🔍 **Automatic SBOM Discovery** - Finds and processes Software Bill of Materials files
- 🧠 **Smart Code Analysis** - Multi-language analyzer detects actual component usage
- 📊 **Vulnerability Assessment** - Determines exploitability using Neo4j graph database
- 📦 **VEX/TIX Generation** - Creates standards-compliant security documents
- 🚀 **FastAPI Backend** - Async, high-performance REST API
- 🔐 **Security First** - Git validation, path sanitization, rate limiting

## 🛠️ Development Requirements

1. **[Docker](https://www.docker.com/)** - Container runtime
2. **[Docker Compose](https://docs.docker.com/compose/)** - Multi-container orchestration
3. **[MongoDB Compass](https://www.mongodb.com/products/compass)** (optional) - MongoDB GUI
4. **[Neo4j Browser](http://localhost:7474)** - Graph database visualization (runs on container)
5. **Python 3.13+** - For local development

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/securechaindev/securechain-vexgen.git
cd securechain-vexgen
```

### 2. Configure Environment Variables
Create a `.env` file from `template.env`:
```bash
cp template.env .env
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
Download [database dumps](https://doi.org/10.5281/zenodo.16739081) from Zenodo, unzip, and run:
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

## 💻 Local Development

### Python Environment Setup

The project uses **Python 3.13** with dependencies managed by `pyproject.toml`.

#### Option 1: Using uv (Recommended)
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Sync dependencies
uv sync

# Run server
uv run uvicorn app.main:app --reload --port 8002
```

#### Option 2: Using pip
```bash
# Create virtual environment
python3.13 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e .

# Run server
uvicorn app.main:app --reload --port 8002
```

### Code Quality
```bash
# Linting
ruff check app/

# Formatting
ruff format app/
```

## 🧪 Testing

The project has comprehensive test coverage (87%) with unit and integration tests.

### Install Test Dependencies

#### Using uv (Recommended)
```bash
uv sync --extra test
```

#### Using pip
```bash
pip install -e ".[test]"
```

### Running Tests

#### Run all tests
```bash
uv run pytest tests/
```

#### Run with coverage report
```bash
uv run pytest tests/ --cov=app --cov-report=term
```

#### Run with detailed HTML coverage report
```bash
uv run pytest tests/ --cov=app --cov-report=html
# Open htmlcov/index.html in your browser
```

#### Run specific test file
```bash
uv run pytest tests/unit/services/test_vex_service.py -v
```

#### Run tests matching a pattern
```bash
uv run pytest tests/ -k "test_analyzer" -v
```

### Test Structure
```
tests/
├── unit/                # Unit tests (87% coverage)
│   ├── code_analyzer/   # Language analyzers
│   ├── controllers/     # API controllers
│   ├── processors/      # SBOM/VEX processors
│   ├── services/        # Business logic
│   └── templates/       # VEX/TIX templates
└── integration/         # Integration tests
```

### Coverage Report
Current coverage: **87%** (475 tests passing)

Key areas covered:
- ✅ All language analyzers (Python, JS/TS, Java, C#, Ruby, Rust)
- ✅ VEX/TIX generation pipeline
- ✅ SBOM processing
- ✅ Service layer (Version, Package, Vulnerability)
- ✅ Templates and exceptions


```
app/
├── main.py              # FastAPI entry point
├── database.py          # DatabaseManager singleton
├── dependencies.py      # ServiceContainer (DI)
├── validators.py        # Security validators
├── constants.py         # Enums and configs
├── controllers/         # API endpoints
├── services/            # Business logic
├── domain/              # Domain logic (DDD)
│   ├── code_analyzer/   # Multi-language analysis
│   └── vex_generation/  # VEX/TIX generation
├── schemas/             # Pydantic models
└── templates/           # VEX/TIX templates
```

For detailed architecture documentation, see **[CLAUDE.md](./CLAUDE.md)** (AI agent context).

## 📁 Project Structure

VEXGen follows **Domain-Driven Design (DDD)** principles:

- **Singleton Pattern**: DatabaseManager, ServiceContainer
- **Dependency Injection**: FastAPI `Depends()`
- **Factory Pattern**: CodeAnalyzerFactory
- **Security Validators**: GitValidator, PathValidator

### Key Technologies
- **FastAPI 0.116.1** - Async REST API
- **MongoDB Motor 3.6.0** - Document storage
- **Neo4j 5.27.0** - Graph database
- **Pydantic v2** - Data validation
- **aiofiles, aiohttp** - Async I/O

## 🔐 Security Features

- ✅ Git URL validation (whitelist: github.com, gitlab.com, bitbucket.org)
- ✅ Path traversal prevention
- ✅ Command injection protection
- ✅ Rate limiting by IP
- ✅ JWT authentication
- ✅ Input validation with Pydantic

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

### Commit Convention
```
feat: new feature
fix: bug fix
docs: documentation
refactor: code refactoring
test: add tests
chore: maintenance
```

## 📄 License

[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html)

## 📞 Contact

- **Team**: Secure Chain Team
- **Email**: [hi@securechain.dev](mailto:hi@securechain.dev)
- **GitHub**: [@securechaindev](https://github.com/securechaindev)
- **Docs**: [securechaindev.github.io](https://securechaindev.github.io/)

## 📚 References

- [VEX Specification](https://www.cisa.gov/resources-tools/resources/minimum-elements-vulnerability-exploitability-exchange-vex)
- [SBOM Standards](https://cyclonedx.org/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---

**Version**: 1.1.0  
**Status**: Production  
**Last Updated**: October 2025
