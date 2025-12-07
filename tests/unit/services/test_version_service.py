from unittest.mock import AsyncMock, Mock

import pytest

from app.database import DatabaseManager
from app.services.version_service import VersionService


@pytest.fixture
def mock_db():
    db = Mock(spec=DatabaseManager)
    driver = Mock()

    mock_session = Mock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    driver.session.return_value = mock_session
    db.get_neo4j_driver.return_value = driver

    return db, mock_session


@pytest.fixture
def version_service(mock_db):
    db, _ = mock_db
    return VersionService(db)


@pytest.mark.asyncio
class TestVersionService:
    @pytest.mark.asyncio
    async def test_read_vulnerability_ids_by_version_and_package_found(
        self, version_service, mock_db
    ):
        _, mock_session = mock_db

        mock_record = Mock()
        mock_record.get = Mock(return_value=["CVE-2023-1234", "CVE-2023-5678"])

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)
        mock_session.run = AsyncMock(return_value=mock_result)

        result = await version_service.read_vulnerability_ids_by_version_and_package(
            "PypiPackage", "django", "3.2.0"
        )

        assert result == ["CVE-2023-1234", "CVE-2023-5678"]
        mock_session.run.assert_called_once()

        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "PypiPackage" in query
        assert "MATCH" in query
        assert call_args[1]["name"] == "django"
        assert call_args[1]["version"] == "3.2.0"

    @pytest.mark.asyncio
    async def test_read_vulnerability_ids_by_version_and_package_not_found(
        self, version_service, mock_db
    ):
        _, mock_session = mock_db

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=None)
        mock_session.run = AsyncMock(return_value=mock_result)

        result = await version_service.read_vulnerability_ids_by_version_and_package(
            "PypiPackage", "unknown", "1.0.0"
        )

        assert result == []

    @pytest.mark.asyncio
    async def test_read_vulnerability_ids_empty_list(
        self, version_service, mock_db
    ):
        _, mock_session = mock_db

        mock_record = Mock()
        mock_record.get = Mock(return_value=[])

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)
        mock_session.run = AsyncMock(return_value=mock_result)

        result = await version_service.read_vulnerability_ids_by_version_and_package(
            "NpmPackage", "express", "4.17.0"
        )

        assert result == []

    @pytest.mark.asyncio
    async def test_different_node_types(self, version_service, mock_db):
        _, mock_session = mock_db

        mock_record = Mock()
        mock_record.get = Mock(return_value="CVE-2024-0001")

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)
        mock_session.run = AsyncMock(return_value=mock_result)

        for node_type in ["PypiPackage", "NpmPackage", "MavenPackage", "GemPackage"]:
            result = await version_service.read_vulnerability_ids_by_version_and_package(
                node_type, "test-package", "1.0.0"
            )

            assert result == "CVE-2024-0001"
            call_args = mock_session.run.call_args[0][0]
            assert node_type in call_args
