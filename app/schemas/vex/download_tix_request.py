from pydantic import BaseModel, Field

from app.schemas.patterns import MONGO_OBJECT_ID_PATTERN


class DownloadTIXRequest(BaseModel):
    tix_id: str = Field(
        ...,
        pattern=MONGO_OBJECT_ID_PATTERN
    )
