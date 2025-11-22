import hashlib
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.exceptions import InvalidTokenException, NotAuthenticatedException
from app.utils.api_key_bearer import ApiKeyBearer


class TestApiKeyBearer:
    @pytest.mark.asyncio
    async def test_hash_generates_correct_sha256(self):
        api_key = "sk_test_key_123"
        expected_hash = hashlib.sha256(api_key.encode()).hexdigest()

        result = ApiKeyBearer.hash(api_key)

        assert result == expected_hash

    @pytest.mark.asyncio
    async def test_call_raises_not_authenticated_when_no_api_key(self):
        bearer = ApiKeyBearer(auto_error=True)
        mock_request = Mock()
        mock_request.headers.get.return_value = None

        with pytest.raises(NotAuthenticatedException):
            await bearer(mock_request)

    @pytest.mark.asyncio
    async def test_call_returns_none_when_no_api_key_and_auto_error_false(self):
        bearer = ApiKeyBearer(auto_error=False)
        mock_request = Mock()
        mock_request.headers.get.return_value = None

        result = await bearer(mock_request)

        assert result is None

    @pytest.mark.asyncio
    async def test_call_raises_invalid_token_when_key_missing_prefix(self):
        bearer = ApiKeyBearer(auto_error=True)
        mock_request = Mock()
        mock_request.headers.get.return_value = "invalid_key_format"

        with pytest.raises(InvalidTokenException):
            await bearer(mock_request)

    @pytest.mark.asyncio
    async def test_call_raises_invalid_token_when_key_not_found(self):
        bearer = ApiKeyBearer(auto_error=True)
        mock_request = Mock()
        mock_request.headers.get.return_value = "sk_test_key_123"

        mock_db_manager = Mock()
        mock_collection = AsyncMock()
        mock_collection.find_one.return_value = None
        mock_db_manager.get_api_keys_collection.return_value = mock_collection

        with patch("app.utils.api_key_bearer.DatabaseManager", return_value=mock_db_manager):
            with pytest.raises(InvalidTokenException):
                await bearer(mock_request)

    @pytest.mark.asyncio
    async def test_call_raises_invalid_token_when_key_is_inactive(self):
        bearer = ApiKeyBearer(auto_error=True)
        mock_request = Mock()
        api_key = "sk_test_key_123"
        mock_request.headers.get.return_value = api_key

        mock_db_manager = Mock()
        mock_collection = AsyncMock()
        mock_collection.find_one.return_value = {
            "key_hash": ApiKeyBearer.hash(api_key),
            "user_id": "user123",
            "is_active": False
        }
        mock_db_manager.get_api_keys_collection.return_value = mock_collection

        with patch("app.utils.api_key_bearer.DatabaseManager", return_value=mock_db_manager):
            with pytest.raises(InvalidTokenException):
                await bearer(mock_request)

    @pytest.mark.asyncio
    async def test_call_returns_user_id_for_valid_active_key(self):
        bearer = ApiKeyBearer(auto_error=True)
        mock_request = Mock()
        api_key = "sk_test_key_123"
        user_id = "user123"
        mock_request.headers.get.return_value = api_key

        mock_db_manager = Mock()
        mock_collection = AsyncMock()
        mock_collection.find_one.return_value = {
            "key_hash": ApiKeyBearer.hash(api_key),
            "user_id": user_id,
            "is_active": True,
            "name": "Test Key"
        }
        mock_db_manager.get_api_keys_collection.return_value = mock_collection

        with patch("app.utils.api_key_bearer.DatabaseManager", return_value=mock_db_manager):
            result = await bearer(mock_request)

            assert result == {"user_id": user_id}

    @pytest.mark.asyncio
    async def test_call_raises_invalid_token_on_malformed_data(self):
        bearer = ApiKeyBearer(auto_error=True)
        mock_request = Mock()
        api_key = "sk_test_key_123"
        mock_request.headers.get.return_value = api_key

        mock_db_manager = Mock()
        mock_collection = AsyncMock()
        mock_collection.find_one.return_value = {
            "key_hash": ApiKeyBearer.hash(api_key),
        }
        mock_db_manager.get_api_keys_collection.return_value = mock_collection

        with patch("app.utils.api_key_bearer.DatabaseManager", return_value=mock_db_manager):
            with pytest.raises(InvalidTokenException):
                await bearer(mock_request)
