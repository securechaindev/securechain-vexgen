from fastapi import HTTPException

from app.constants import ResponseCode, ResponseMessage


class VexNotFoundException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=404,
            detail={"code": ResponseCode.ERROR_VEX_NOT_FOUND, "message": ResponseMessage.ERROR_VEX_NOT_FOUND}
        )
