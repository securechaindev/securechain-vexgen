from pydantic import BaseModel, Field

from app.schemas.patterns import MONGO_OBJECT_ID_PATTERN


class DownloadVEXRequest(BaseModel):
    vex_id: str = Field(
        ...,
        pattern=MONGO_OBJECT_ID_PATTERN
    )


class DownloadTIXRequest(BaseModel):
    tix_id: str = Field(
        ...,
        pattern=MONGO_OBJECT_ID_PATTERN
    )


class GenerateVEXTIXRequest(BaseModel):
    owner: str = Field(min_lengt=1)
    name: str = Field(min_length=1)
    Field(
        ...,
        pattern=MONGO_OBJECT_ID_PATTERN
    )
