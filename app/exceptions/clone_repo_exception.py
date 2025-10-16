from fastapi import HTTPException


class CloneRepoException(HTTPException):
    def __init__(self):
        super().__init__(status_code=500, detail="clone_repo_exception")
