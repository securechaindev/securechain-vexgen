from fastapi import HTTPException


class ComponentNotSupportedException(HTTPException):
    def __init__(self):
        super().__init__(status_code=500, detail="component_not_supported")
