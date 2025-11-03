from fastapi import HTTPException

from app.constants import ResponseCode, ResponseMessage


class TixNotFoundException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=404,
            detail={"code": ResponseCode.ERROR_TIX_NOT_FOUND, "message": ResponseMessage.ERROR_TIX_NOT_FOUND}
        )
