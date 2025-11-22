# 🤖 AI Agent Context - SecureChain VEXGen

> **Context file for AI agents (Claude, GPT, etc.)**  
> Last updated: November 8, 2025  
> Project version: 1.1.1

---

## 📋 Project Overview

**SecureChain VEXGen** is a tool to automatically generate **VEX (Vulnerability Exploitability eXchange)** and **TIX (Threat Intelligence eXchange)** documents from GitHub repositories.

### What does it do?
1. Clones GitHub repositories
2. Finds SBOM (Software Bill of Materials) files
3. Analyzes code to detect usage of vulnerable components
4. Generates VEX documents indicating if vulnerabilities are exploitable
5. Generates TIX documents with threat intelligence information

---

## 🏗️ Project Architecture

### Tech Stack
- **Framework:** FastAPI 0.116.1 (Python 3.14+)
- **Databases:**
  - MongoDB (PyMongo 4.15.4) - Stores VEX/TIX documents
  - Neo4j (5.27.0) - Dependency and vulnerability graph
- **Async I/O:** aiofiles, aiohttp
- **Validation:** Pydantic v2
- **Git:** GitPython
- **Rate Limiting:** slowapi

### Folder Structure

```
securechain-vexgen/
├── app/
│   ├── main.py                    # FastAPI entry point
│   ├── config.py                  # Pydantic settings
│   ├── database.py                # DatabaseManager singleton
│   ├── dependencies.py            # ServiceContainer (DI)
│   ├── validators.py              # GitValidator, PathValidator
│   ├── constants.py               # Enums and configs
│   ├── logger.py                  # Custom logger
│   ├── limiter.py                 # Rate limiting
│   ├── router.py                  # Main router
│   ├── middleware.py              # Custom middleware
│   ├── exception_handler.py       # Exception handling
│   │
│   ├── controllers/               # FastAPI endpoints
│   │   ├── health_controller.py  # Health check
│   │   ├── vex_controller.py     # VEX CRUD
│   │   ├── tix_controller.py     # TIX CRUD
│   │   └── vex_tix_controller.py # VEX/TIX generation
│   │
│   ├── services/                  # Application logic
│   │   ├── vex_service.py        # VEX CRUD in MongoDB
│   │   ├── tix_service.py        # TIX CRUD in MongoDB
│   │   ├── package_service.py    # Neo4j queries (packages)
│   │   ├── version_service.py    # Neo4j queries (versions)
│   │   └── vulnerability_service.py # MongoDB queries (CVEs)
│   │
│   ├── domain/                    # Domain logic (DDD)
│   │   ├── code_analyzer/         # Code analysis
│   │   │   ├── analyzer_factory.py
│   │   │   └── analyzers/
│   │   │       ├── py_code_analyzer.py
│   │   │       ├── js_ts_code_analyzer.py
│   │   │       ├── java_code_analyzer.py
│   │   │       ├── cs_code_analyzer.py
│   │   │       ├── rb_code_analyzer.py
│   │   │       └── rs_code_analyzer.py
│   │   │
│   │   └── vex_generation/        # VEX/TIX generation
│   │       ├── processors/        # Orchestrators
│   │       │   ├── sbom_processor.py
│   │       │   ├── statement_generator.py
│   │       │   └── vex_tix_initializer.py
│   │       ├── generators/        # Template generators
│   │       │   ├── vex_statement_generator.py
│   │       │   ├── tix_statement_generator.py
│   │       │   └── statement_helpers.py
│   │       ├── parsers/           # Parsers and transformers
│   │       │   ├── purl_parser.py
│   │       │   └── node_type_mapper.py
│   │       ├── infrastructure/    # External access
│   │       │   └── repository_downloader.py
│   │       └── helpers/           # Utilities
│   │           └── path_helper.py
│   │
│   ├── schemas/                   # Pydantic models
│   │   ├── commons/               # Shared models
│   │   │   ├── mongo.py           # MongoObjectId, VEXIdPath, TIXIdPath
│   │   │   ├── node_type.py       # NodeType Enum
│   │   │   └── processed_sbom_result.py  # ProcessedSBOMResult
│   │   ├── tix/                   # TIX specific models
│   │   │   └── tix.py             # TIXBase, TIXCreate, TIXResponse
│   │   ├── vex/                   # VEX specific models
│   │   │   └── vex.py             # VEXBase, VEXCreate, VEXResponse
│   │   └── vex_tix/               # VEX/TIX generation models
│   │       └── generate_vex_tix_request.py  # owner, name (no user_id)
│   │
│   ├── templates/                 # VEX/TIX templates
│   │   ├── file/                  # File templates
│   │   │   ├── vex_template.py
│   │   │   └── tix_template.py
│   │   └── statement/             # Statement templates
│   │       ├── vex_statement_template.py
│   │       └── tix_statement_template.py
│   │
│   ├── exceptions/                # Custom exceptions
│   │   ├── clone_repo_exception.py
│   │   ├── invalid_repository_exception.py
│   │   ├── invalid_sbom_exception.py
│   │   ├── sbom_not_found_exception.py
│   │   └── ...
│   │
│   ├── apis/                      # External clients
│   │   └── github_service.py     # GitHub GraphQL client
│   │
│   └── utils/                     # Generic utilities
│       ├── json_encoder.py        # JSON serialization
│       ├── jwt_bearer.py          # JWT authentication (sync)
│       ├── api_key_bearer.py      # API key authentication (async)
│       └── dual_auth_bearer.py    # Dual authentication orchestrator
│
├── pyproject.toml                 # Dependencies (uv/pip)
├── README.md                      # User documentation
├── CLAUDE.md                      # This file (AI context)
└── Dockerfile                     # Containerization
```

---

## 🔑 Key Concepts

### 1. **Design Patterns Implemented**

#### Singleton Pattern
```python
# DatabaseManager - Single instance for entire app
class DatabaseManager:
    instance: "DatabaseManager | None" = None
    
    def __new__(cls) -> "DatabaseManager":
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

# LoggerManager - Custom logger with singleton pattern
class LoggerManager:
    instance: "LoggerManager | None" = None
    initialized: bool = False
    
    def __new__(cls, *args, **kwargs):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

# ServiceContainer - Manages all services
class ServiceContainer:
    instance: "ServiceContainer | None" = None
    # Lazy initialization of services
```

#### Dependency Injection (Complete Implementation)
```python
# ServiceContainer manages ALL dependencies including utilities and security
class ServiceContainer:
    vex_service: VEXService | None = None
    tix_service: TIXService | None = None
    json_encoder: JSONEncoder | None = None      # ✨ Utilities also injected
    jwt_bearer: JWTBearer | None = None          # ✨ JWT authentication
    api_key_bearer: ApiKeyBearer | None = None   # ✨ API Key authentication
    dual_auth_bearer: DualAuthBearer | None = None # ✨ Dual auth (API Key + JWT)

# In controllers - everything is injected:
async def get_vexs(
    request: Request,
    vex_service: VEXService = Depends(get_vex_service),
    json_encoder: JSONEncoder = Depends(get_json_encoder)  # Injected!
) -> JSONResponse:
    vexs = await vex_service.read_user_vexs(user_id)
    return JSONResponse(content=json_encoder.encode({...}))

# Authentication via DI (not direct instantiation):
@router.get("/endpoint", dependencies=[Depends(get_dual_auth_bearer())])
async def protected_endpoint():
    # Dual authentication: API Key or JWT
    pass
```

**Key Point:** ALL components (services, utilities, security) follow the same DI pattern. 
No direct instantiation (`JSONEncoder()`, `JWTBearer()`, `ApiKeyBearer()`) in controllers.

#### Factory Pattern
```python
# CodeAnalyzerFactory - Creates analyzers based on language
analyzer = CodeAnalyzerFactory.create_analyzer(file_extension)
```

#### Template Method Pattern
```python
# VEX/TIX generators inherit from base templates
class VEXStatementGenerator:
    async def generate_vex_statement(self, vulnerability_data):
        # Template method
```

---

### 2. **VEX/TIX Generation Flow**

```
1. POST /vex_tix/generate (owner, name in body - user_id from token)
   ↓
2. Controller extracts user_id from authentication payload
   user_id = payload.get("user_id")
   ↓
3. SBOMProcessor.process_sboms(user_id passed as parameter)
   ├─ RepositoryDownloader.download_repository()  # Clone repo (async via to_thread)
   ├─ find_sbom_files()                           # Find SBOMs
   ├─ GitHubService.get_last_commit_date()       # Check cache
   └─ VEXTIXInitializer.init_vex_tix()           # Generate docs
      ↓
4. StatementsGenerator.generate_statements()
   ├─ For each component in SBOM:
   │  ├─ PackageService.read_package_by_name()   # Neo4j
   │  ├─ VersionService.read_vulnerabilities()   # Neo4j
   │  └─ VulnerabilityService.get_vuln_details() # MongoDB
   │
   ├─ VEXStatementGenerator.generate_vex_statement()
   │  └─ Calculate priority with scoring
   │
   └─ TIXStatementGenerator.generate_tix_statement()
      └─ CodeAnalyzer.is_relevant()              # Analyze code
         └─ Detect imports/component usage
      ↓
5. Save to MongoDB with user_id (VEXService, TIXService)
   await vex_service.update_user_vexs(vex_id, user_id)
   await tix_service.update_user_tixs(tix_id, user_id)
   ↓
6. Return ZIP with VEX + TIX
```

---

### 3. **Data Models**

#### VEX Document (MongoDB)
```python
{
    "_id": ObjectId("..."),
    "owner": "owner-name",
    "name": "repo-name",
    "sbom_path": "path/to/sbom.json",
    "sbom_name": "sbom.json",
    "moment": ISODate("2025-10-20T..."),
    "statements": [
        {
            "vulnerability": {
                "name": "CVE-2024-1234",
                "description": "...",
                "priority": 8.5
            },
            "status": "affected",
            "justification": "...",
            "action_statement": "..."
        }
    ],
    "metadata": { ... },
    "user_vexs": ["user_id1", "user_id2"]
}
```

#### TIX Document (MongoDB)
Similar to VEX but with threat intelligence and code analysis information.

#### Neo4j Graph
```cypher
// Nodes
(Package {name: "requests", type: "PythonPackage"})
(Version {name: "2.28.0", vulnerabilities: ["CVE-..."]})
(Vulnerability {id: "CVE-2024-1234"})

// Relationships
(Package)-[:HAVE]->(Version)
(Version)-[:HAS_VULNERABILITY]->(Vulnerability)
```

---

## 🔒 Security Implementation

### Dual Authentication System

The application supports **two authentication methods** with priority-based fallback:

```python
# Priority order:
1. API Key (X-API-Key header) - Priority 1
2. JWT Token (access_token cookie) - Fallback
```

#### API Key Authentication
```python
# ApiKeyBearer - Async authentication with MongoDB validation
class ApiKeyBearer(HTTPBearer):
    async def __call__(self, request: Request) -> dict[str, str]:
        # 1. Extract X-API-Key header
        # 2. Validate "sk_" prefix
        # 3. SHA256 hash the key
        # 4. Query MongoDB for key_hash
        # 5. Verify key is active
        # 6. Return {"user_id": "..."}

# API Key format: sk_xxxxxxxxxxxxxxxx
# Storage: SHA256-hashed in MongoDB with is_active flag
# Use case: Machine-to-machine, CI/CD pipelines
```

#### JWT Authentication
```python
# JWTBearer - Synchronous token validation
class JWTBearer(HTTPBearer):
    def __call__(self, request: Request) -> dict[str, Any]:
        # 1. Extract access_token cookie
        # 2. Verify with JWT secret key
        # 3. Decode payload
        # 4. Return user claims

# Note: Synchronous (not async) because jwt.decode() is CPU-bound
# No I/O operations - just cryptographic validation
# Use case: Web application, user sessions
```

#### Dual Auth Bearer
```python
# DualAuthBearer - Orchestrates both authentication methods
class DualAuthBearer(HTTPBearer):
    async def __call__(self, request: Request) -> dict[str, Any]:
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return await self.api_key_bearer(request)  # async
        return self.jwt_bearer(request)  # sync (no await)

# Priority: API Key > JWT
# Injected via dependency: Depends(get_dual_auth_bearer())
```

**Design Rationale:**
- `ApiKeyBearer`: **async** - MongoDB I/O operation (`find_one`)
- `JWTBearer`: **sync** - Only CPU-bound cryptographic operations
- `DualAuthBearer`: **async** - Delegates to ApiKeyBearer (which is async)

#### Usage in Controllers
```python
# Protected endpoint with dual authentication
@router.get("/tix/user")  # No user_id in path anymore
async def get_tixs(
    request: Request,
    payload: dict = Depends(get_dual_auth_bearer()),  # Get auth payload
    tix_service: TIXService = Depends(get_tix_service)
):
    # Extract user_id from authentication payload
    user_id = payload.get("user_id")
    
    # Fetch user's TIX documents
    tixs = await tix_service.read_user_tixs(user_id)
    return JSONResponse(content={"data": tixs})

# Download TIX endpoint - RESTful GET with path parameter
@router.get("/tix/download/{tix_id}")
async def download_tix(
    request: Request,
    path: TIXIdPath = Depends(),  # Path parameter validation
    tix_service: TIXService = Depends(get_tix_service)
):
    tix = await tix_service.read_tix_by_id(path.tix_id)
    # Return ZIP file...

# Download VEX endpoint - RESTful GET with path parameter  
@router.get("/vex/download/{vex_id}")
async def download_vex(
    request: Request,
    path: VEXIdPath = Depends(),  # Path parameter validation
    vex_service: VEXService = Depends(get_vex_service)
):
    vex = await vex_service.read_vex_by_id(path.vex_id)
    # Return ZIP file...

# VEX/TIX generation - user_id from token, not body
@router.post("/vex_tix/generate")
async def generate_vex_tix(
    request: Request,
    generate_request: GenerateVEXTIXRequest = Body(),  # No user_id field
    payload: dict = Depends(get_dual_auth_bearer()),
    vex_service: VEXService = Depends(get_vex_service),
    tix_service: TIXService = Depends(get_tix_service)
):
    user_id = payload.get("user_id")  # From token
    # Process with user_id from authentication
    processor = SBOMProcessor(generate_request, ..., user_id)
    # ...
```

**Security & RESTful Design:**
- **Before:** User could pass any `user_id` in path/body → Potential impersonation
- **After:** `user_id` extracted from verified token → Secure user identification
- **Download Endpoints:** Changed from `POST /download` with body to `GET /download/{id}` with path parameter (RESTful)
- **Pattern:** All user-specific endpoints now use token-based user identification
- **Validation:** Path parameters validated using `TIXIdPath` and `VEXIdPath` Pydantic models

### GitValidator
```python
# Validates Git repository URLs
- Only HTTPS/HTTP allowed
- Host whitelist: github.com, gitlab.com, bitbucket.org
- Blocks file://, git://, ssh://
- Prevents command injection (`, $, ;, |, &)
- Validates GitHub format: https://github.com/owner/repo.git
```

### PathValidator
```python
# Sanitizes file paths
- Prevents path traversal (../, ~/, \0)
- Validates allowed extensions (.json for SBOM)
- Verifies paths are within base directory
- Blocks dangerous characters
```

### Rate Limiting
```python
# slowapi - Limits by IP
RateLimit.DEFAULT = "25/minute"
RateLimit.DOWNLOAD = "5/minute"
```

### Exception Handling
```python
# Standardized error responses with code and message
class CustomException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=404,
            detail={"code": "error_code", "message": "Human-readable message"}
        )

# All responses follow consistent format:
{
    "code": "success_vex_retrieved",      # For programmatic handling
    "message": "VEX document retrieved successfully"  # For users
}

# Available exceptions:
# - VexNotFoundException, TixNotFoundException
# - ExpiredTokenException, InvalidTokenException, NotAuthenticatedException
# - InvalidRepositoryException, CloneRepoException
# - SbomNotFoundException, ComponentNotSupportedException
```

---

## 🗄️ Database Management

### DatabaseManager
```python
# Singleton with connection pooling
- MongoDB: minPoolSize=10, maxPoolSize=100
- Neo4j: max_connection_pool_size=100
- Lifecycle: initialize() at startup, close() at shutdown
```

### MongoDB Collections
- `securechain.vexs` - VEX documents
- `securechain.tixs` - TIX documents
- `securechain.users` - Users (reference)
- `vulnerabilities.vulnerabilities` - CVEs
- `vulnerabilities.cwes` - Common Weakness Enumeration
- `vulnerabilities.exploits` - Known exploits

---

## 📝 Logging

### LoggerManager (Singleton)
```python
# Custom logger with singleton pattern to avoid circular imports
from app.logger import logger

logger.info("Message")
logger.warning("Warning message")
logger.error("Error message")
logger.exception("Exception with traceback")
logger.debug("Debug message")

# Configuration:
- File: app/logs/errors.log
- Level: INFO
- Rotation: 5MB max, 5 backups
- Format: timestamp - level - name - file:line - message
```

**Important:** The logger uses a custom singleton pattern (not via dependencies.py) 
to avoid circular import issues. Import directly: `from app.logger import logger`

---

## 💉 Dependency Injection Architecture

### ServiceContainer Components (All Injected)

```python
ServiceContainer (Singleton)
├── DatabaseManager          # Infrastructure
├── VEXService              # Business logic
├── TIXService              # Business logic  
├── PackageService          # Data access
├── VersionService          # Data access
├── VulnerabilityService    # Data access
├── JSONEncoder             # Utility - JSON serialization
├── JWTBearer               # Security - JWT authentication (sync)
├── ApiKeyBearer            # Security - API key authentication (async)
└── DualAuthBearer          # Security - Dual authentication orchestrator
```

**Important:** ALL components are managed by `ServiceContainer`, including utilities 
and all authentication classes. This ensures:
- Single instance across the app (Singleton)
- Easy testing (mock via `app.dependency_overrides`)
- Consistent pattern (no direct instantiation)
- Centralized lifecycle management

### Usage Example
```python
# ❌ WRONG - Direct instantiation
json_encoder = JSONEncoder()
jwt_bearer = JWTBearer()
api_key_bearer = ApiKeyBearer()

# ✅ CORRECT - Dependency Injection
from app.dependencies import get_json_encoder, get_dual_auth_bearer

async def endpoint(
    json_encoder: JSONEncoder = Depends(get_json_encoder),
    auth: dict = Depends(get_dual_auth_bearer())  # Dual auth
):
    # Use injected dependencies
    # auth contains user_id from either API key or JWT
    return JSONResponse(content=json_encoder.encode({...}))
```

---

## 🎯 Code Conventions

### Type Hints
```python
# Always use complete type hints
async def create_vex(self, vex: VEXCreate) -> str:
    # ...

def get_vex_service() -> VEXService:
    # ...
```

### Async/Await
```python
# All I/O operations are async
async def read_file(path: str):
    async with aiofiles.open(path, 'r') as f:
        return await f.read()
```

### Pydantic Models
```python
# ConfigDict for aliases and validation
class VEXResponse(VEXBase):
    model_config = ConfigDict(populate_by_name=True)
    id: str = Field(..., alias="_id")
```

### Organized Imports
```python
# 1. Standard library
from os import walk
from typing import Any

# 2. Third-party
from fastapi import APIRouter
from pymongo import AsyncMongoClient

# 3. Local app
from app.config import settings
from app.services import VEXService
```

---

## 🧪 Testing

### Current Status
- **Coverage:** 88% (493 tests passing)
- **Test Framework:** pytest 8.4.2 + pytest-asyncio 1.2.0 + pytest-cov
- **Test Duration:** ~5 seconds
- **Last Updated:** November 8, 2025

### Test Structure
```
tests/
├── conftest.py                      # Global pytest fixtures
├── unit/                            # Unit tests (87% coverage)
│   ├── code_analyzer/               # Language analyzers (98-100%)
│   │   ├── test_python_analyzer.py
│   │   ├── test_javascript_typescript_analyzer.py
│   │   ├── test_java_analyzer.py
│   │   ├── test_csharp_analyzer.py
│   │   ├── test_ruby_analyzer.py
│   │   ├── test_rust_analyzer.py
│   │   └── test_code_validator.py
│   │
│   ├── processors/                  # SBOM/VEX processors (96-100%)
│   │   ├── test_sbom_processor.py
│   │   ├── test_statement_generator.py
│   │   └── test_vex_tix_initializer.py
│   │
│   ├── services/                    # Business logic (100%)
│   │   ├── test_vex_service.py
│   │   ├── test_tix_service.py
│   │   ├── test_version_service.py
│   │   ├── test_package_service.py
│   │   └── test_vulnerability_service.py
│   │
│   ├── templates/                   # VEX/TIX templates (100%)
│   │   └── test_templates.py
│   │
│   ├── exceptions/                  # Custom exceptions (100%)
│   │   └── test_exceptions.py
│   │
│   ├── validators/                  # Path validation (100%)
│   │   └── test_path_validator.py
│   │
│   ├── utils/                       # Authentication utilities (100%)
│   │   ├── test_api_key_bearer.py   # API key authentication (8 tests)
│   │   └── test_dual_auth_bearer.py # Dual authentication (7 tests)
│   │
│   └── parsers/                     # Parsers and utilities (90-100%)
│       ├── test_purl_parser.py
│       └── test_node_type_mapper.py
│
└── integration/                     # Integration tests (API endpoints)
    ├── test_health_controller.py    # Health check endpoint (2 tests)
    ├── test_vex_controller.py       # VEX endpoints (1 test)
    ├── test_tix_controller.py       # TIX endpoints (2 tests)
    └── test_vex_tix_controller.py   # VEX/TIX generation (5 tests)
```

### Installing Test Dependencies

#### Using uv (Recommended)
```bash
# Sync all dependencies including test extras
uv sync --extra test

# Or sync everything (dev + test)
uv sync --all-extras
```

#### Using pip
```bash
# Install with test dependencies
pip install -e ".[test]"

# Or install all optional dependencies
pip install -e ".[dev,test]"
```

### Running Tests

#### Basic Test Execution
```bash
# Run all tests
uv run pytest tests/

# Run with verbose output
uv run pytest tests/ -v

# Run specific test file
uv run pytest tests/unit/services/test_vex_service.py -v

# Run tests matching pattern
uv run pytest tests/ -k "test_analyzer" -v

# Run only failed tests from last run
uv run pytest tests/ --lf

# Run tests in parallel (faster)
uv run pytest tests/ -n auto
```

#### Coverage Reports
```bash
# Terminal coverage report
uv run pytest tests/ --cov=app --cov-report=term

# HTML coverage report (detailed)
uv run pytest tests/ --cov=app --cov-report=html
# Then open: htmlcov/index.html

# XML coverage report (for CI/CD)
uv run pytest tests/ --cov=app --cov-report=xml

# Show missing lines
uv run pytest tests/ --cov=app --cov-report=term-missing

# Coverage with specific threshold
uv run pytest tests/ --cov=app --cov-fail-under=85
```

#### Quiet Mode (CI-Friendly)
```bash
# Minimal output
uv run pytest tests/ -q

# Quiet with coverage
uv run pytest tests/ --cov=app --cov-report=term -q
```

### Testing Patterns

#### 1. Mocking Async Services (Neo4j, MongoDB)

**Neo4j AsyncSession Mocking:**
```python
import pytest
from unittest.mock import AsyncMock, MagicMock

@pytest.mark.asyncio
async def test_read_package_by_name():
    """Test reading package from Neo4j."""
    # Mock Neo4j session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.single.return_value = {"p": {"name": "requests"}}
    mock_session.run.return_value = mock_result
    
    # Mock session context manager
    mock_session.__aenter__.return_value = mock_session
    mock_session.__aexit__.return_value = None
    
    # Use mock in service
    service = PackageService(db_manager)
    db_manager.neo4j_driver.session.return_value = mock_session
    
    result = await service.read_package_by_name("requests", "pypi")
    assert result["name"] == "requests"
```

**MongoDB Aggregation Mocking:**
```python
@pytest.mark.asyncio
async def test_get_vulnerability_count():
    """Test MongoDB aggregation pipeline."""
    # Mock aggregation cursor
    mock_cursor = AsyncMock()
    mock_cursor.__aiter__.return_value = iter([{"count": 42}])
    
    # Mock collection
    mock_collection = MagicMock()
    mock_collection.aggregate.return_value = mock_cursor
    
    # Use in service
    service = VulnerabilityService(db_manager)
    db_manager.db["vulnerabilities"].aggregate = mock_collection.aggregate
    
    result = await service.get_vulnerability_count()
    assert result == 42
```

#### 2. Testing FastAPI Endpoints (Dependency Injection)

```python
from fastapi.testclient import TestClient
from app.main import app
from app.dependencies import get_vex_service

def test_get_vexs_endpoint():
    """Test VEX list endpoint with DI override."""
    # Create mock service
    mock_vex_service = MagicMock(spec=VEXService)
    mock_vex_service.read_user_vexs.return_value = [
        {"id": "123", "name": "test-vex"}
    ]
    
    # Override dependency
    app.dependency_overrides[get_vex_service] = lambda: mock_vex_service
    
    # Test endpoint
    client = TestClient(app)
    response = client.get("/api/v1/vex", headers={"user-id": "user123"})
    
    assert response.status_code == 200
    assert len(response.json()["vexs"]) == 1
    
    # Cleanup
    app.dependency_overrides.clear()
```

#### 3. Testing Code Analyzers

```python
@pytest.mark.asyncio
async def test_python_import_detection():
    """Test Python analyzer detects imports."""
    code = """
    import requests
    from flask import Flask
    
    app = Flask(__name__)
    response = requests.get('https://api.example.com')
    """
    
    analyzer = PythonCodeAnalyzer()
    result = await analyzer.is_relevant(
        component_name="requests",
        local_dir="/tmp/test"
    )
    
    assert result is True
```

#### 4. Testing Exception Handling

```python
import pytest
from app.exceptions import InvalidSBOMException

def test_invalid_sbom_exception():
    """Test custom exception attributes."""
    exception = InvalidSBOMException("Invalid format")
    
    assert exception.status_code == 400
    assert exception.detail == "Invalid format"
    assert str(exception) == "Invalid format"
```

### Important Testing Notes

#### ⚠️ Async Test Decorator Pattern
```python
# ❌ WRONG - Class-level decorator applies to ALL methods
@pytest.mark.asyncio
class TestMyClass:
    def test_sync_method(self):      # Gets decorator → Warning!
        pass
    
    async def test_async_method(self):
        pass

# ✅ CORRECT - Decorator only on async methods
class TestMyClass:
    def test_sync_method(self):      # No decorator
        pass
    
    @pytest.mark.asyncio
    async def test_async_method(self):  # Decorator here
        pass
```

**Rationale:** pytest-asyncio applies class-level decorators to ALL methods, 
causing warnings for non-async methods. Always apply `@pytest.mark.asyncio` 
only to individual async methods, never to the class.

#### Fixture Scope
```python
# Session-scoped for expensive setup
@pytest.fixture(scope="session")
def db_manager():
    return DatabaseManager()

# Function-scoped for test isolation
@pytest.fixture
def mock_vex_service():
    return MagicMock(spec=VEXService)
```

### Coverage Areas

**Fully Covered (95-100%):**
- ✅ Language analyzers (Python, JS/TS, Java, C#, Ruby, Rust)
- ✅ VEX/TIX generation pipeline
- ✅ SBOM processing
- ✅ Service layer (VEX, TIX, Version, Package, Vulnerability)
- ✅ Templates (VEX/TIX file and statement)
- ✅ Custom exceptions
- ✅ Authentication utilities (ApiKeyBearer, DualAuthBearer) - **NEW**
- ✅ PURL parser
- ✅ Node type mapper

**Partially Covered (50-70%):**
- ⚠️ Controllers (health: 100%, others: 53-61%)
- ⚠️ Validators (58%)
- ⚠️ Utilities (json_encoder: 56%, jwt_bearer: 52%)

**Low Coverage (<50%):**
- ❌ GitHub API service (38%)
- ❌ Database initialization (32%)
- ❌ HTTP session management (44%)

**Not Covered:**
- ❌ Integration tests with real databases
- ❌ End-to-end tests
- ❌ Performance/load tests

### CI/CD Integration

**GitHub Actions Example:**
```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install uv
        run: curl -LsSf https://astral.sh/uv/install.sh | sh
      
      - name: Install dependencies
        run: uv sync --extra test
      
      - name: Run tests with coverage
        run: uv run pytest tests/ --cov=app --cov-report=xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
```

### Useful Fixtures

```python
# conftest.py - Global fixtures

import pytest
from unittest.mock import MagicMock, AsyncMock

@pytest.fixture
def mock_db_manager():
    """Mock DatabaseManager for unit tests."""
    db = MagicMock()
    db.neo4j_driver = MagicMock()
    db.mongo_client = MagicMock()
    db.db = MagicMock()
    return db

@pytest.fixture
def mock_neo4j_session():
    """Mock Neo4j async session."""
    session = AsyncMock()
    session.__aenter__.return_value = session
    session.__aexit__.return_value = None
    return session

@pytest.fixture
def sample_sbom():
    """Sample SBOM for testing."""
    return {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "name": "requests",
                "version": "2.28.0",
                "purl": "pkg:pypi/requests@2.28.0"
            }
        ]
    }
```

---

## 🚀 Useful Commands

### Local Development

#### Option 1: Using uv (Recommended - Fast!)
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Sync dependencies (creates venv automatically)
uv sync

# Sync with dev dependencies
uv sync --extra dev

# Sync with test dependencies
uv sync --extra test

# Sync with all extras (dev + test)
uv sync --all-extras

# Run server
uv run uvicorn app.main:app --reload --port 8002

# Run with specific Python version
uv run --python 3.14 uvicorn app.main:app --reload --port 8002

# Install additional package
uv pip install package-name

# Linting
uv run ruff check app/

# Format
uv run ruff format app/

# Run tests
uv run pytest tests/

# Run tests with coverage
uv run pytest tests/ --cov=app --cov-report=term

# Generate HTML coverage report
uv run pytest tests/ --cov=app --cov-report=html
```

#### Option 2: Using pip/venv
```bash
# Create venv
python3.14 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -e .

# Install with dev dependencies
pip install -e ".[dev]"

# Install with test dependencies
pip install -e ".[test]"

# Install with all optional dependencies
pip install -e ".[dev,test]"

# Run server
uvicorn app.main:app --reload --port 8002

# Linting
ruff check app/

# Format
ruff format app/

# Run tests
pytest tests/

# Run tests with coverage
pytest tests/ --cov=app --cov-report=term
```

### Docker

#### Production Build
```bash
# Build production image (multi-stage with uv)
docker build -t vexgen:latest .

# Run production container
docker run -p 8002:8000 --env-file .env vexgen:latest
```

#### Development with Docker Compose
```bash
# Build and run dev environment (hot reload with uv)
docker compose -f dev/docker-compose.yml up --build

# Run in detached mode
docker compose -f dev/docker-compose.yml up -d

# View logs
docker compose -f dev/docker-compose.yml logs -f

# Stop containers
docker compose -f dev/docker-compose.yml down
```

---

## 🐛 Debugging

### Logs
```python
# Logs in: app/logs/errors.log
from app.logger import logger

logger.info("Message")
logger.error("Error message")
logger.exception("Exception with traceback")
```

### API Response Format
All API responses follow a consistent format with `code` and `message`:
```json
{
    "vex": {...},
    "code": "success_vex_retrieved",
    "message": "VEX document retrieved successfully"
}
```

Error responses:
```json
{
    "code": "error_vex_not_found",
    "message": "VEX document not found"
}
```

### Health Check
```bash
# Check service status
curl http://localhost:8002/api/v1/health
```

### MongoDB
```bash
# Compass GUI: mongodb://localhost:27017
# Check connection:
db.adminCommand({ ping: 1 })
```

### Neo4j
```bash
# Browser: http://localhost:7474
# Test Cypher query:
MATCH (n:PythonPackage) RETURN n LIMIT 10
```

---

## ⚠️ Common Issues

### 1. "Database not initialized"
```python
# Solution: Ensure lifespan executes
await db_manager.initialize()
```

### 2. "Import could not be resolved"
```python
# Solution: Reload Python Language Server
# VSCode: Ctrl+Shift+P -> "Python: Restart Language Server"
```

### 3. Rate limit exceeded
```python
# Solution: Configure limits in constants.py
class RateLimit(str, Enum):
    DEFAULT = "25/minute"  # Increase if needed
```

### 4. Git clone timeout
```python
# Solution: Increase timeout in constants.py
class GitRules:
    GIT_TIMEOUT_SECONDS = 300  # Increase if needed
```

### 5. Circular import with logger
```python
# Solution: Logger uses its own singleton pattern
# Always import directly:
from app.logger import logger  # ✅ Correct
# NOT from dependencies:
# from app.dependencies import get_logger  # ❌ Doesn't exist
```

---

## 📝 High Priority TODOs

1. **Testing - Remaining Areas**
   - [ ] Integration tests with real MongoDB/Neo4j instances
   - [ ] End-to-end tests for complete VEX/TIX generation flow
   - [ ] Increase controller coverage with authenticated requests (currently 54-60%)
   - [ ] Increase utility coverage (encoders: 52-56%, GitHub API: 38%)

2. **Observability**
   - [ ] Metrics with Prometheus
   - [ ] Enhanced health check with DB connectivity
   - [ ] Structured logging (JSON format)
   - [ ] Distributed tracing (OpenTelemetry)

3. **Performance**
   - [ ] Redis cache for frequently accessed data
   - [ ] Configurable timeouts for external services
   - [ ] Retry logic with exponential backoff
   - [ ] Query optimization for Neo4j

4. **CI/CD**
   - [ ] Pre-commit hooks (ruff, tests)
   - [ ] Performance benchmarks

---

## 📚 References

### External Documentation
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [Pydantic V2 Docs](https://docs.pydantic.dev/latest/)
- [PyMongo (MongoDB Async)](https://pymongo.readthedocs.io/en/stable/api/pymongo/asynchronous/index.html)
- [Neo4j Python Driver](https://neo4j.com/docs/python-manual/current/)
- [VEX Spec](https://www.cisa.gov/resources-tools/resources/minimum-elements-vulnerability-exploitability-exchange-vex)

### Standards
- **SBOM:** CycloneDX, SPDX
- **VEX:** OpenVEX, CSAF VEX
- **Package URLs:** PURL specification

---

## 🤝 Contributing

### Workflow
1. Fork the repository
2. Create branch: `git checkout -b feature/new-feature`
3. Commit: `git commit -m "feat: description"`
4. Push: `git push origin feature/new-feature`
5. Open Pull Request

### Commit Messages
```
feat: new feature
fix: bug fix
docs: documentation update
refactor: refactoring without functionality change
test: add tests
chore: maintenance tasks
```

---

## 📞 Contact

- **Team:** Secure Chain Team
- **Email:** hi@securechain.dev
- **GitHub:** https://github.com/securechaindev
- **Docs:** https://securechaindev.github.io/

---

## 📄 License

GNU General Public License v3.0 or later  
See [LICENSE](./LICENSE) for more details.

---
