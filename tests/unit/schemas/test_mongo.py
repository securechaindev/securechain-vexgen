import pytest
from pydantic import ValidationError

from app.schemas import MongoObjectId, TIXIdPath, VEXIdPath


class TestMongoObjectId:
    def test_valid_mongo_object_id(self):
        data = {"id": "507f1f77bcf86cd799439011"}
        obj = MongoObjectId(**data)
        assert obj.id == "507f1f77bcf86cd799439011"

    def test_valid_24_hex_chars(self):
        data = {"id": "abcdef1234567890abcdef12"}
        obj = MongoObjectId(**data)
        assert obj.id == "abcdef1234567890abcdef12"

    def test_invalid_mongo_object_id_too_short(self):
        data = {"id": "507f1f77bcf86cd79943901"}
        with pytest.raises(ValidationError) as exc_info:
            MongoObjectId(**data)
        errors = exc_info.value.errors()
        assert any(e["type"] == "string_pattern_mismatch" for e in errors)

    def test_invalid_mongo_object_id_too_long(self):
        data = {"id": "507f1f77bcf86cd7994390111"}
        with pytest.raises(ValidationError) as exc_info:
            MongoObjectId(**data)
        errors = exc_info.value.errors()
        assert any(e["type"] == "string_pattern_mismatch" for e in errors)

    def test_invalid_mongo_object_id_non_hex(self):
        data = {"id": "507f1f77bcf86cd799439g11"}
        with pytest.raises(ValidationError) as exc_info:
            MongoObjectId(**data)
        errors = exc_info.value.errors()
        assert any(e["type"] == "string_pattern_mismatch" for e in errors)

    def test_valid_mongo_object_id_uppercase(self):
        data = {"id": "507F1F77BCF86CD799439011"}
        obj = MongoObjectId(**data)
        assert obj.id == "507F1F77BCF86CD799439011"

    def test_valid_mongo_object_id_mixed_case(self):
        data = {"id": "507f1F77BcF86cD799439011"}
        obj = MongoObjectId(**data)
        assert obj.id == "507f1F77BcF86cD799439011"


class TestVEXIdPath:
    def test_valid_vex_id_path(self):
        data = {"vex_id": "507f1f77bcf86cd799439011"}
        path = VEXIdPath(**data)
        assert path.vex_id == "507f1f77bcf86cd799439011"

    def test_invalid_vex_id_path(self):
        data = {"vex_id": "invalid-id"}
        with pytest.raises(ValidationError) as exc_info:
            VEXIdPath(**data)
        errors = exc_info.value.errors()
        assert any(e["type"] == "string_pattern_mismatch" for e in errors)


class TestTIXIdPath:
    def test_valid_tix_id_path(self):
        data = {"tix_id": "507f1f77bcf86cd799439012"}
        path = TIXIdPath(**data)
        assert path.tix_id == "507f1f77bcf86cd799439012"

    def test_invalid_tix_id_path(self):
        data = {"tix_id": "invalid-id"}
        with pytest.raises(ValidationError) as exc_info:
            TIXIdPath(**data)
        errors = exc_info.value.errors()
        assert any(e["type"] == "string_pattern_mismatch" for e in errors)
