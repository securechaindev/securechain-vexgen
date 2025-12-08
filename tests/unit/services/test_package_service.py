from unittest.mock import AsyncMock, Mock

import pytest

from app.database import DatabaseManager
from app.services.package_service import PackageService


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
def package_service(mock_db):
    db, _ = mock_db
    return PackageService(db)


@pytest.mark.asyncio
class TestPackageService:
    @pytest.mark.asyncio
    async def test_read_package_by_name_found(self, package_service, mock_db):
        _, mock_session = mock_db

        mock_record = Mock()
        mock_record.get = Mock(return_value={
            "name": "django",
            "import_names": ["django", "django.conf", "django.db", "org.django"]
        })

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)
        mock_session.run = AsyncMock(return_value=mock_result)

        result = await package_service.read_package_by_name(
            "PypiPackage", "django"
        )

        assert result is not None
        assert result["name"] == "django"
        assert "django" in result["import_names"]
        assert "django.conf" in result["import_names"]
        assert len(result["import_names"]) == 4

    @pytest.mark.asyncio
    async def test_read_package_by_name_not_found(self, package_service, mock_db):
        _, mock_session = mock_db

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=None)
        mock_session.run = AsyncMock(return_value=mock_result)

        result = await package_service.read_package_by_name(
            "PypiPackage", "nonexistent"
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_read_package_query_structure(self, package_service, mock_db):
        _, mock_session = mock_db

        mock_record = Mock()
        mock_record.get = Mock(return_value={
            "name": "test",
            "import_names": ["test", ""]
        })

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)
        mock_session.run = AsyncMock(return_value=mock_result)

        await package_service.read_package_by_name("PypiPackage", "test")

        call_args = mock_session.run.call_args
        query = call_args[0][0]

        assert "MATCH" in query
        assert "PypiPackage" in query
        assert "p.name" in query
        assert "coalesce" in query
        assert "import_names" in query
        assert "group_id" in query
        assert call_args[1]["name"] == "test"

    @pytest.mark.asyncio
    async def test_read_package_with_group_id(self, package_service, mock_db):
        _, mock_session = mock_db

        mock_record = Mock()
        mock_record.get = Mock(return_value={
            "name": "commons-lang3",
            "import_names": ["org.apache.commons", "commons-lang3", "org.apache.commons"]
        })

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)
        mock_session.run = AsyncMock(return_value=mock_result)

        result = await package_service.read_package_by_name(
            "MavenPackage", "commons-lang3"
        )

        assert result is not None
        assert result["name"] == "commons-lang3"
        assert "org.apache.commons" in result["import_names"]

    @pytest.mark.asyncio
    async def test_read_package_different_node_types(self, package_service, mock_db):
        _, mock_session = mock_db

        mock_record = Mock()
        mock_record.get = Mock(return_value={
            "name": "test-package",
            "import_names": ["test-package", ""]
        })

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)
        mock_session.run = AsyncMock(return_value=mock_result)

        for node_type in ["PypiPackage", "NpmPackage", "MavenPackage", "GemPackage"]:
            result = await package_service.read_package_by_name(
                node_type, "test-package"
            )

            assert result is not None
            assert result["name"] == "test-package"
            assert isinstance(result["import_names"], list)
            assert "test-package" in result["import_names"]
            call_args = mock_session.run.call_args[0][0]
            assert node_type in call_args

    @pytest.mark.asyncio
    async def test_read_package_returns_dict_or_none(self, package_service, mock_db):
        _, mock_session = mock_db

        mock_record = Mock()
        mock_record.get = Mock(return_value={
            "name": "pkg",
            "import_names": ["pkg", ""]
        })

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)
        mock_session.run = AsyncMock(return_value=mock_result)

        result = await package_service.read_package_by_name("PypiPackage", "pkg")
        assert isinstance(result, dict)
        assert "name" in result
        assert "import_names" in result

        mock_result.single = AsyncMock(return_value=None)
        result = await package_service.read_package_by_name("PypiPackage", "nonexistent")
        assert result is None
