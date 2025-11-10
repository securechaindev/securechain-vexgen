from datetime import datetime
from unittest.mock import AsyncMock, Mock

import pytest
from bson import ObjectId

from app.database import DatabaseManager
from app.schemas import VEXCreate
from app.services.vex_service import VEXService
from app.utils import JSONEncoder


@pytest.fixture
def mock_db():
    db = Mock(spec=DatabaseManager)
    db.get_vexs_collection = Mock(return_value=AsyncMock())
    db.get_user_collection = Mock(return_value=AsyncMock())
    return db


@pytest.fixture
def mock_json_encoder():
    encoder = Mock(spec=JSONEncoder)
    encoder.encode = Mock(side_effect=lambda x: x)
    return encoder


@pytest.fixture
def vex_service(mock_db, mock_json_encoder):
    return VEXService(mock_db, mock_json_encoder)


@pytest.fixture
def sample_vex_create():
    return VEXCreate(
        owner="test-owner",
        name="test-repo",
        sbom_path="/path/to/sbom.json",
        sbom_name="sbom.json",
        moment=datetime.now(),
        statements=[{"id": "stmt-1", "status": "not_affected"}],
        metadata={"key": "value"}
    )


@pytest.fixture
def sample_vex_dict():
    return {
        "_id": "507f1f77bcf86cd799439011",
        "owner": "test-owner",
        "name": "test-repo",
        "sbom_path": "/path/to/sbom.json",
        "sbom_name": "sbom.json",
        "moment": datetime.now(),
        "statements": [{"id": "stmt-1", "status": "not_affected"}]
    }


class TestVEXService:
    @pytest.mark.asyncio
    async def test_create_vex(self, vex_service, mock_db, sample_vex_create):
        mock_result = Mock()
        mock_result.upserted_id = ObjectId("507f1f77bcf86cd799439011")
        mock_db.get_vexs_collection().replace_one = AsyncMock(return_value=mock_result)

        vex_id = await vex_service.create_vex(sample_vex_create)

        assert vex_id == "507f1f77bcf86cd799439011"
        mock_db.get_vexs_collection().replace_one.assert_called_once()

    @pytest.mark.asyncio
    async def test_read_vex_by_id_found(self, vex_service, mock_db, sample_vex_dict):
        mock_db.get_vexs_collection().find_one = AsyncMock(return_value=sample_vex_dict)

        vex = await vex_service.read_vex_by_id("507f1f77bcf86cd799439011")

        assert vex is not None
        assert vex.id == "507f1f77bcf86cd799439011"
        assert vex.owner == "test-owner"

    @pytest.mark.asyncio
    async def test_read_vex_by_id_not_found(self, vex_service, mock_db):
        mock_db.get_vexs_collection().find_one = AsyncMock(return_value=None)

        vex = await vex_service.read_vex_by_id("507f1f77bcf86cd799439011")

        assert vex is None

    @pytest.mark.asyncio
    async def test_read_vex_by_owner_name_sbom_name_found(self, vex_service, mock_db, sample_vex_dict):
        mock_db.get_vexs_collection().find_one = AsyncMock(return_value=sample_vex_dict)

        vex = await vex_service.read_vex_by_owner_name_sbom_name("test-owner", "test-repo", "/path/to/sbom.json")

        assert vex is not None
        assert vex.owner == "test-owner"

    @pytest.mark.asyncio
    async def test_read_vex_by_owner_name_sbom_name_not_found(self, vex_service, mock_db):
        mock_db.get_vexs_collection().find_one = AsyncMock(return_value=None)

        vex = await vex_service.read_vex_by_owner_name_sbom_name("test-owner", "test-repo", "/path/to/sbom.json")

        assert vex is None

    @pytest.mark.asyncio
    async def test_read_user_vexs_success(self, vex_service, mock_db, sample_vex_dict):
        async def async_generator():
            yield sample_vex_dict

        mock_db.get_user_collection().aggregate = Mock(return_value=async_generator())

        vexs = await vex_service.read_user_vexs("507f1f77bcf86cd799439011")

        assert len(vexs) == 1
        assert vexs[0].owner == "test-owner"

    @pytest.mark.asyncio
    async def test_read_user_vexs_exception(self, vex_service, mock_db):
        mock_db.get_user_collection().aggregate = Mock(side_effect=Exception("DB Error"))

        vexs = await vex_service.read_user_vexs("507f1f77bcf86cd799439011")

        assert vexs == []

    @pytest.mark.asyncio
    async def test_update_user_vexs(self, vex_service, mock_db):
        mock_db.get_user_collection().update_one = AsyncMock()

        await vex_service.update_user_vexs("507f1f77bcf86cd799439011", "507f1f77bcf86cd799439012")

        mock_db.get_user_collection().update_one.assert_called_once()
