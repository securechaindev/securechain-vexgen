from fastapi import HTTPException

from app.constants import ResponseCode, ResponseMessage


class ComponentNotSupportedException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=500,
            detail={"code": ResponseCode.COMPONENT_NOT_SUPPORTED, "message": ResponseMessage.COMPONENT_NOT_SUPPORTED}
        )
