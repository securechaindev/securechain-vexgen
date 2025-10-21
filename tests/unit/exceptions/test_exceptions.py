import pytest
from fastapi import HTTPException

from app.exceptions.expired_token_exception import ExpiredTokenException
from app.exceptions.invalid_repository_exception import InvalidRepositoryException
from app.exceptions.invalid_sbom_exception import InvalidSbomException
from app.exceptions.invalid_token_exception import InvalidTokenException
from app.exceptions.not_authenticated_exception import NotAuthenticatedException


class TestExpiredTokenException:
    def test_expired_token_exception_creation(self):
        exc = ExpiredTokenException()

        assert isinstance(exc, HTTPException)
        assert exc.status_code == 401
        assert exc.detail == "token_expired"

    def test_expired_token_exception_can_be_raised(self):
        with pytest.raises(ExpiredTokenException) as exc_info:
            raise ExpiredTokenException()

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "token_expired"


class TestInvalidTokenException:
    def test_invalid_token_exception_creation(self):
        exc = InvalidTokenException()

        assert isinstance(exc, HTTPException)
        assert exc.status_code == 401
        assert exc.detail == "invalid_token"

    def test_invalid_token_exception_can_be_raised(self):
        with pytest.raises(InvalidTokenException) as exc_info:
            raise InvalidTokenException()

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "invalid_token"


class TestNotAuthenticatedException:
    def test_not_authenticated_exception_creation(self):
        exc = NotAuthenticatedException()

        assert isinstance(exc, HTTPException)
        assert exc.status_code == 401
        assert exc.detail == "not_authenticated"

    def test_not_authenticated_exception_can_be_raised(self):
        with pytest.raises(NotAuthenticatedException) as exc_info:
            raise NotAuthenticatedException()

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "not_authenticated"


class TestInvalidRepositoryException:
    def test_invalid_repository_exception_creation(self):
        exc = InvalidRepositoryException()

        assert isinstance(exc, HTTPException)
        assert exc.status_code == 404
        assert exc.detail == "repository_not_found"

    def test_invalid_repository_exception_can_be_raised(self):
        with pytest.raises(InvalidRepositoryException) as exc_info:
            raise InvalidRepositoryException()

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail == "repository_not_found"


class TestInvalidSBOMException:
    def test_invalid_sbom_exception_creation(self):
        exc = InvalidSbomException()

        assert isinstance(exc, HTTPException)
        assert exc.status_code == 500
        assert exc.detail == "invalid_sbom"

    def test_invalid_sbom_exception_can_be_raised(self):
        with pytest.raises(InvalidSbomException) as exc_info:
            raise InvalidSbomException()

        assert exc_info.value.status_code == 500
        assert exc_info.value.detail == "invalid_sbom"


class TestExceptionInheritance:
    def test_all_exceptions_inherit_from_http_exception(self):
        exceptions = [
            ExpiredTokenException(),
            InvalidTokenException(),
            NotAuthenticatedException(),
            InvalidRepositoryException(),
            InvalidSbomException()
        ]

        for exc in exceptions:
            assert isinstance(exc, HTTPException)

    def test_exception_status_codes(self):
        auth_exceptions = [
            ExpiredTokenException(),
            InvalidTokenException(),
            NotAuthenticatedException()
        ]

        assert InvalidRepositoryException().status_code == 404
        assert InvalidSbomException().status_code == 500

        for exc in auth_exceptions:
            assert exc.status_code == 401

    def test_exception_details_are_strings(self):
        exceptions = [
            ExpiredTokenException(),
            InvalidTokenException(),
            NotAuthenticatedException(),
            InvalidRepositoryException(),
            InvalidSbomException()
        ]

        for exc in exceptions:
            assert isinstance(exc.detail, str)
            assert len(exc.detail) > 0
