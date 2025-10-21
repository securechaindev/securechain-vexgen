from datetime import datetime

import pytest
from pydantic import ValidationError

from app.schemas import TIXBase, TIXCreate, TIXResponse


class TestTIXBase:
    def test_valid_tix_base(self):
        data = {
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json"
        }
        tix = TIXBase(**data)
        assert tix.owner == "test-owner"
        assert tix.name == "test-repo"
        assert tix.sbom_path == "/path/to/sbom.json"
        assert tix.sbom_name is None
        assert tix.moment is None

    def test_tix_base_with_all_fields(self):
        moment = datetime.now()
        data = {
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json",
            "sbom_name": "sbom.json",
            "moment": moment
        }
        tix = TIXBase(**data)
        assert tix.sbom_name == "sbom.json"
        assert tix.moment == moment

    def test_tix_base_strips_whitespace(self):
        data = {
            "owner": "  test-owner  ",
            "name": "  test-repo  ",
            "sbom_path": "  /path/to/sbom.json  "
        }
        tix = TIXBase(**data)
        assert tix.owner == "test-owner"
        assert tix.name == "test-repo"
        assert tix.sbom_path == "/path/to/sbom.json"

    def test_tix_base_empty_owner_fails(self):
        data = {
            "owner": "",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json"
        }
        with pytest.raises(ValidationError) as exc_info:
            TIXBase(**data)
        errors = exc_info.value.errors()
        assert any(e["type"] == "string_too_short" for e in errors)

    def test_tix_base_owner_too_long_fails(self):
        data = {
            "owner": "a" * 256,
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json"
        }
        with pytest.raises(ValidationError) as exc_info:
            TIXBase(**data)
        errors = exc_info.value.errors()
        assert any(e["type"] == "string_too_long" for e in errors)

    def test_tix_base_missing_required_field_fails(self):
        data = {
            "owner": "test-owner",
            "name": "test-repo"
        }
        with pytest.raises(ValidationError) as exc_info:
            TIXBase(**data)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("sbom_path",) for e in errors)


class TestTIXCreate:
    def test_valid_tix_create(self):
        data = {
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json"
        }
        tix = TIXCreate(**data)
        assert tix.owner == "test-owner"
        assert tix.statements == []
        assert tix.metadata is None

    def test_tix_create_with_statements(self):
        data = {
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json",
            "statements": [{"id": "stmt-1", "status": "exploitable"}]
        }
        tix = TIXCreate(**data)
        assert len(tix.statements) == 1
        assert tix.statements[0]["id"] == "stmt-1"

    def test_tix_create_with_metadata(self):
        data = {
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json",
            "metadata": {"key": "value"}
        }
        tix = TIXCreate(**data)
        assert tix.metadata == {"key": "value"}


class TestTIXResponse:
    def test_valid_tix_response(self):
        data = {
            "_id": "507f1f77bcf86cd799439012",
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json",
            "statements": []
        }
        tix = TIXResponse(**data)
        assert tix.id == "507f1f77bcf86cd799439012"
        assert tix.owner == "test-owner"

    def test_tix_response_alias_id(self):
        data = {
            "_id": "507f1f77bcf86cd799439012",
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json",
            "statements": []
        }
        tix = TIXResponse(**data)
        dumped = tix.model_dump(by_alias=True)
        assert "_id" in dumped
        assert dumped["_id"] == "507f1f77bcf86cd799439012"

    def test_tix_response_populate_by_name(self):
        data = {
            "id": "507f1f77bcf86cd799439012",
            "owner": "test-owner",
            "name": "test-repo",
            "sbom_path": "/path/to/sbom.json",
            "statements": []
        }
        tix = TIXResponse(**data)
        assert tix.id == "507f1f77bcf86cd799439012"
