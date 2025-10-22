from unittest.mock import AsyncMock, Mock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import DatabaseManager
from app.dependencies import ServiceContainer
from app.main import app


@pytest.fixture
def mock_db_manager():
    db_manager = Mock(spec=DatabaseManager)
    db_manager.get_vexs_collection = Mock(return_value=AsyncMock())
    db_manager.get_tixs_collection = Mock(return_value=AsyncMock())
    db_manager.get_user_collection = Mock(return_value=AsyncMock())
    db_manager.get_vulnerabilities_collection = Mock(return_value=AsyncMock())
    db_manager.get_neo4j_driver = Mock(return_value=AsyncMock())
    db_manager.initialize = AsyncMock()
    db_manager.close = AsyncMock()
    return db_manager


@pytest.fixture
def mock_service_container(mock_db_manager):
    container = Mock(spec=ServiceContainer)
    container.get_db = Mock(return_value=mock_db_manager)
    return container


@pytest_asyncio.fixture
async def client(mock_db_manager):
    with patch.object(DatabaseManager, "__new__", return_value=mock_db_manager):
        with patch.object(ServiceContainer, "get_db", return_value=mock_db_manager):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                yield ac


@pytest.fixture
def sample_vex_data():
    return {
        "_id": "507f1f77bcf86cd799439011",
        "owner": "test-owner",
        "name": "test-repo",
        "sbom_path": "sbom.json",
        "sbom_name": "sbom.json",
        "moment": "2025-10-20T10:00:00Z",
        "statements": [],
        "metadata": {},
        "user_vexs": ["user123"]
    }


@pytest.fixture
def sample_tix_data():
    return {
        "_id": "507f1f77bcf86cd799439012",
        "owner": "test-owner",
        "name": "test-repo",
        "sbom_path": "sbom.json",
        "sbom_name": "sbom.json",
        "moment": "2025-10-20T10:00:00Z",
        "statements": [],
        "metadata": {},
        "user_tixs": ["user123"]
    }
