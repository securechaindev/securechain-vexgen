from pydantic import BaseModel, Field

from app.schemas.patterns import MONGO_OBJECT_ID_PATTERN


class MongoObjectId(BaseModel):
    id: str = Field(
        ...,
        pattern=MONGO_OBJECT_ID_PATTERN,
        examples=["507f1f77bcf86cd799439011"]
    )


class VEXIdPath(BaseModel):
    vex_id: str = Field(..., pattern=MONGO_OBJECT_ID_PATTERN)


class TIXIdPath(BaseModel):
    tix_id: str = Field(..., pattern=MONGO_OBJECT_ID_PATTERN)
