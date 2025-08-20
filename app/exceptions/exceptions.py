from fastapi import HTTPException


class InvalidSbomException(HTTPException):
    def __init__(self):
        super().__init__(status_code=500, code="invalid_sbom")


class InvalidRepositoryException(HTTPException):
    def __init__(self):
        super().__init__(status_code=404, code="repository_not_found")


class SbomNotFoundException(HTTPException):
    def __init__(self):
        super().__init__(status_code=404, code="sbom_not_found")


class CloneRepoException(HTTPException):
    def __init__(self):
        super().__init__(status_code=500, code="clone_repo_exception")


class NotAuthenticatedException(HTTPException):
    def __init__(self):
        super().__init__(status_code=401, code="not_authenticated")


class ExpiredTokenException(HTTPException):
    def __init__(self):
        super().__init__(status_code=401, code="token_expired")


class InvalidTokenException(HTTPException):
    def __init__(self):
        super().__init__(status_code=401, code="invalid_token")


class ComponentNotSupportedException(HTTPException):
    def __init__(self):
        super().__init__(status_code=500, code="component_not_supported")
