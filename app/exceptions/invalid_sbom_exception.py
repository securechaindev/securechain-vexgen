from fastapi import HTTPException


class InvalidSbomException(HTTPException):
    def __init__(self):
        super().__init__(status_code=500, detail="invalid_sbom")
