from datetime import datetime

import pytest
from pydantic import ValidationError

from app.schemas import VEXBase, VEXCreate, VEXResponse


class TestVEXBase:
    def test_valid_vex_base(self):
        data = {
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json"
        }
        vex = VEXBase(**data)
        assert vex.owner == "test-owner"
        assert vex.name == "test-repo"
        assert vex.sbom_path == "/path/to/sbom.json"
        assert vex.sbom_name is None
        assert vex.moment is None

    def test_vex_base_with_all_fields(self):
        moment = datetime.now()
        data = {
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json",
            "sbom_name": "sbom.json",
            "moment": moment
        }
        vex = VEXBase(**data)
        assert vex.sbom_name == "sbom.json"
        assert vex.moment == moment

    def test_vex_base_strips_whitespace(self):
        data = {
            "owner": "  test-owner  ",
            "name": "  test-repo  ",
            "sbom_path": "  /path/to/sbom.json  "
        }
        vex = VEXBase(**data)
        assert vex.owner == "test-owner"
        assert vex.name == "test-repo"
        assert vex.sbom_path == "/path/to/sbom.json"

    def test_vex_base_empty_owner_fails(self):
        data = {
            "owner": "",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json"
        }
        with pytest.raises(ValidationError) as exc_info:
            VEXBase(**data)
        errors = exc_info.value.errors()
        assert any(e["type"] == "string_too_short" for e in errors)

    def test_vex_base_owner_too_long_fails(self):
        data = {
            "owner": "a" * 256,
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json"
        }
        with pytest.raises(ValidationError) as exc_info:
            VEXBase(**data)
        errors = exc_info.value.errors()
        assert any(e["type"] == "string_too_long" for e in errors)

    def test_vex_base_missing_required_field_fails(self):
        data = {
            "owner": "test-owner",
            "name": "test-repo"
        }
        with pytest.raises(ValidationError) as exc_info:
            VEXBase(**data)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("sbom_path",) for e in errors)


class TestVEXCreate:
    def test_valid_vex_create(self):
        data = {
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json"
        }
        vex = VEXCreate(**data)
        assert vex.owner == "test-owner"
        assert vex.metadata is None

    def test_vex_create_with_metadata(self):
        data = {
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json",
            "metadata": {"key": "value"}
        }
        vex = VEXCreate(**data)
        assert vex.metadata == {"key": "value"}


class TestVEXResponse:
    def test_valid_vex_response(self):
        data = {
            "_id": "507f1f77bcf86cd799439011",
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json",
            "statements": []
        }
        vex = VEXResponse(**data)
        assert vex.id == "507f1f77bcf86cd799439011"
        assert vex.owner == "test-owner"

    def test_vex_response_alias_id(self):
        data = {
            "_id": "507f1f77bcf86cd799439011",
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json",
            "statements": []
        }
        vex = VEXResponse(**data)
        dumped = vex.model_dump(by_alias=True)
        assert "_id" in dumped
        assert dumped["_id"] == "507f1f77bcf86cd799439011"

    def test_vex_response_populate_by_name(self):
        data = {
            "id": "507f1f77bcf86cd799439011",
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json",
            "statements": []
        }
        vex = VEXResponse(**data)
        assert vex.id == "507f1f77bcf86cd799439011"
