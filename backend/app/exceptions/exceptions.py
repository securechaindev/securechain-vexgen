from fastapi import HTTPException


class InvalidMavenComponentException(HTTPException):
    def __init__(self):
        super().__init__(status_code=400, detail="A Maven dependency component is not well built. A group attribute is needed or name should follow the pattern <group_id>:<artifact_id>.")

class InvalidSbomException(HTTPException):
    def __init__(self):
        super().__init__(status_code=400, detail="No valid components found in any SBOM file")

class InvalidRepositoryException(HTTPException):
    def __init__(self):
        super().__init__(status_code=404, detail="Repository not found")

class SbomNotFoundException(HTTPException):
    def __init__(self):
        super().__init__(status_code=404, detail="No SBOM files found in the repository")
