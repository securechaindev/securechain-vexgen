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

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(
            return_value=["django", ["django", "django.conf", "django.db", "org.django"]]
        )
        mock_session.run = AsyncMock(return_value=mock_result)

        package_name, imports = await package_service.read_package_by_name(
            "PypiPackage", "django"
        )

        assert package_name == "django"
        assert "django" in imports
        assert "django.conf" in imports
        assert len(imports) == 4

    @pytest.mark.asyncio
    async def test_read_package_by_name_not_found(self, package_service, mock_db):
        _, mock_session = mock_db

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=None)
        mock_session.run = AsyncMock(return_value=mock_result)

        package_name, imports = await package_service.read_package_by_name(
            "PypiPackage", "nonexistent"
        )

        assert package_name is None
        assert imports is None

    @pytest.mark.asyncio
    async def test_read_package_query_structure(self, package_service, mock_db):
        _, mock_session = mock_db

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=["test", ["test", ""]])
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

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(
            return_value=["commons-lang3", ["org.apache.commons", "commons-lang3", "org.apache.commons"]]
        )
        mock_session.run = AsyncMock(return_value=mock_result)

        package_name, imports = await package_service.read_package_by_name(
            "MavenPackage", "commons-lang3"
        )

        assert package_name == "commons-lang3"
        assert "org.apache.commons" in imports

    @pytest.mark.asyncio
    async def test_read_package_different_node_types(self, package_service, mock_db):
        _, mock_session = mock_db

        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=["test-package", ["test-package", ""]])
        mock_session.run = AsyncMock(return_value=mock_result)

        for node_type in ["PypiPackage", "NpmPackage", "MavenPackage", "GemPackage"]:
            package_name, imports = await package_service.read_package_by_name(
                node_type, "test-package"
            )

            assert package_name == "test-package"
            assert isinstance(imports, list)
            assert "test-package" in imports
            call_args = mock_session.run.call_args[0][0]
            assert node_type in call_args

    @pytest.mark.asyncio
    async def test_read_package_returns_tuple(self, package_service, mock_db):
        _, mock_session = mock_db

        mock_result = AsyncMock()

        mock_result.single = AsyncMock(return_value=["pkg", ["pkg", ""]])
        mock_session.run = AsyncMock(return_value=mock_result)

        result = await package_service.read_package_by_name("PypiPackage", "pkg")
        assert isinstance(result, tuple)
        assert len(result) == 2

        mock_result.single = AsyncMock(return_value=None)
        result = await package_service.read_package_by_name("PypiPackage", "nonexistent")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert result == (None, None)
