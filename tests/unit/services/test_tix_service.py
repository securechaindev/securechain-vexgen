from datetime import datetime
from unittest.mock import AsyncMock, Mock

import pytest
from bson import ObjectId

from app.database import DatabaseManager
from app.schemas.tix.tix import TIXCreate
from app.services.tix_service import TIXService
from app.utils import JSONEncoder


@pytest.fixture
def mock_db():
    db = Mock(spec=DatabaseManager)
    db.get_tixs_collection = Mock(return_value=AsyncMock())
    db.get_users_collection = Mock(return_value=AsyncMock())
    return db


@pytest.fixture
def mock_json_encoder():
    encoder = Mock(spec=JSONEncoder)
    encoder.encode = Mock(side_effect=lambda x: x)
    return encoder


@pytest.fixture
def tix_service(mock_db, mock_json_encoder):
    return TIXService(mock_db, mock_json_encoder)


@pytest.fixture
def sample_tix_create():
    return TIXCreate(
        owner="test-owner",
        name="test-repo",
        sbom_path="/path/to/sbom.json",
        sbom_name="sbom.json",
        moment=datetime.now(),
        statements=[{"id": "stmt-1", "status": "exploitable"}],
        metadata={"key": "value"}
    )


@pytest.fixture
def sample_tix_dict():
    return {
        "_id": "507f1f77bcf86cd799439012",
        "owner": "test-owner",
        "name": "test-repo",
        "sbom_path": "/path/to/sbom.json",
        "sbom_name": "sbom.json",
        "moment": datetime.now(),
        "statements": [{"id": "stmt-1", "status": "exploitable"}]
    }


class TestTIXService:
    @pytest.mark.asyncio
    async def test_create_tix(self, tix_service, mock_db, sample_tix_create):
        mock_result = Mock()
        mock_result.upserted_id = ObjectId("507f1f77bcf86cd799439012")
        mock_db.get_tixs_collection().replace_one = AsyncMock(return_value=mock_result)

        tix_id = await tix_service.create_tix(sample_tix_create)

        assert tix_id == "507f1f77bcf86cd799439012"
        mock_db.get_tixs_collection().replace_one.assert_called_once()

    @pytest.mark.asyncio
    async def test_read_tix_by_id_found(self, tix_service, mock_db, sample_tix_dict):
        mock_db.get_tixs_collection().find_one = AsyncMock(return_value=sample_tix_dict)

        tix = await tix_service.read_tix_by_id("507f1f77bcf86cd799439012")

        assert tix is not None
        assert tix.id == "507f1f77bcf86cd799439012"
        assert tix.owner == "test-owner"

    @pytest.mark.asyncio
    async def test_read_tix_by_id_not_found(self, tix_service, mock_db):
        mock_db.get_tixs_collection().find_one = AsyncMock(return_value=None)

        tix = await tix_service.read_tix_by_id("507f1f77bcf86cd799439012")

        assert tix is None

    @pytest.mark.asyncio
    async def test_read_tix_by_owner_name_sbom_name_found(self, tix_service, mock_db, sample_tix_dict):
        mock_db.get_tixs_collection().find_one = AsyncMock(return_value=sample_tix_dict)

        tix = await tix_service.read_tix_by_owner_name_sbom_name("test-owner", "test-repo", "/path/to/sbom.json")

        assert tix is not None
        assert tix.owner == "test-owner"

    @pytest.mark.asyncio
    async def test_read_tix_by_owner_name_sbom_name_not_found(self, tix_service, mock_db):
        mock_db.get_tixs_collection().find_one = AsyncMock(return_value=None)

        tix = await tix_service.read_tix_by_owner_name_sbom_name("test-owner", "test-repo", "/path/to/sbom.json")

        assert tix is None

    @pytest.mark.asyncio
    async def test_read_user_tixs_success(self, tix_service, mock_db, sample_tix_dict):
        async def async_generator():
            yield sample_tix_dict

        mock_db.get_users_collection().aggregate = Mock(return_value=async_generator())

        tixs = await tix_service.read_user_tixs("507f1f77bcf86cd799439011")

        assert len(tixs) == 1
        assert tixs[0].owner == "test-owner"

    @pytest.mark.asyncio
    async def test_read_user_tixs_exception(self, tix_service, mock_db):
        mock_db.get_users_collection().aggregate = Mock(side_effect=Exception("DB Error"))

        tixs = await tix_service.read_user_tixs("507f1f77bcf86cd799439011")

        assert tixs == []

    @pytest.mark.asyncio
    async def test_update_user_tixs(self, tix_service, mock_db):
        mock_db.get_users_collection().update_one = AsyncMock()

        await tix_service.update_user_tixs("507f1f77bcf86cd799439012", "507f1f77bcf86cd799439011")

        mock_db.get_users_collection().update_one.assert_called_once()
