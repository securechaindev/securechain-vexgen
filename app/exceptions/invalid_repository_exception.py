from fastapi import HTTPException

from app.constants import ResponseCode, ResponseMessage


class InvalidRepositoryException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=404,
            detail={"code": ResponseCode.REPOSITORY_NOT_FOUND, "message": ResponseMessage.REPOSITORY_NOT_FOUND}
        )
