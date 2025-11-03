from fastapi import HTTPException

from app.constants import ResponseCode, ResponseMessage


class CloneRepoException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=500,
            detail={"code": ResponseCode.CLONE_REPO_EXCEPTION, "message": ResponseMessage.CLONE_REPO_EXCEPTION}
        )
