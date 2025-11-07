from unittest.mock import AsyncMock, Mock

import pytest

from app.utils.dual_auth_bearer import DualAuthBearer


class TestDualAuthBearer:
    @pytest.mark.asyncio
    async def test_call_uses_api_key_bearer_when_api_key_present(self):
        bearer = DualAuthBearer()
        mock_request = Mock()
        mock_request.headers.get.return_value = "sk_test_key_123"

        expected_result = {"user_id": "user123"}
        bearer.api_key_bearer = AsyncMock(return_value=expected_result)
        bearer.jwt_bearer = AsyncMock()

        result = await bearer(mock_request)

        bearer.api_key_bearer.assert_called_once_with(mock_request)
        bearer.jwt_bearer.assert_not_called()
        assert result == expected_result

    @pytest.mark.asyncio
    async def test_call_uses_jwt_bearer_when_no_api_key(self):
        bearer = DualAuthBearer()
        mock_request = Mock()
        mock_request.headers.get.return_value = None

        expected_result = {"user_id": "user456", "email": "test@example.com"}
        bearer.api_key_bearer = AsyncMock()
        bearer.jwt_bearer = Mock(return_value=expected_result)

        result = await bearer(mock_request)

        bearer.jwt_bearer.assert_called_once_with(mock_request)
        bearer.api_key_bearer.assert_not_called()
        assert result == expected_result

    @pytest.mark.asyncio
    async def test_call_prioritizes_api_key_over_jwt(self):
        bearer = DualAuthBearer()
        mock_request = Mock()
        mock_request.headers.get.return_value = "sk_test_key_123"
        mock_request.cookies.get.return_value = "jwt_token_value"

        api_key_result = {"user_id": "api_user"}
        jwt_result = {"user_id": "jwt_user"}
        bearer.api_key_bearer = AsyncMock(return_value=api_key_result)
        bearer.jwt_bearer = Mock(return_value=jwt_result)

        result = await bearer(mock_request)

        bearer.api_key_bearer.assert_called_once_with(mock_request)
        bearer.jwt_bearer.assert_not_called()
        assert result == api_key_result

    @pytest.mark.asyncio
    async def test_init_creates_jwt_bearer_with_custom_cookie_name(self):
        custom_cookie = "custom_token"
        bearer = DualAuthBearer(cookie_name=custom_cookie)

        assert bearer.jwt_bearer.cookie_name == custom_cookie

    @pytest.mark.asyncio
    async def test_init_creates_jwt_bearer_with_default_cookie_name(self):
        bearer = DualAuthBearer()

        assert bearer.jwt_bearer.cookie_name == "access_token"

    @pytest.mark.asyncio
    async def test_call_propagates_api_key_exceptions(self):
        from app.exceptions import InvalidTokenException

        bearer = DualAuthBearer()
        mock_request = Mock()
        mock_request.headers.get.return_value = "sk_invalid_key"

        bearer.api_key_bearer = AsyncMock(side_effect=InvalidTokenException())
        bearer.jwt_bearer = AsyncMock()

        with pytest.raises(InvalidTokenException):
            await bearer(mock_request)

        bearer.api_key_bearer.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_propagates_jwt_exceptions(self):
        from app.exceptions import ExpiredTokenException

        bearer = DualAuthBearer()
        mock_request = Mock()
        mock_request.headers.get.return_value = None

        bearer.api_key_bearer = AsyncMock()
        bearer.jwt_bearer = Mock(side_effect=ExpiredTokenException())

        with pytest.raises(ExpiredTokenException):
            await bearer(mock_request)

        bearer.jwt_bearer.assert_called_once()
