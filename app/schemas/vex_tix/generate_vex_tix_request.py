from pydantic import BaseModel, Field, field_validator

from app.schemas.patterns import MONGO_OBJECT_ID_PATTERN
from app.validators import GitValidator


class GenerateVEXTIXRequest(BaseModel):
    owner: str = Field(min_length=1)
    name: str = Field(min_length=1)
    user_id: str = Field(
        ...,
        pattern=MONGO_OBJECT_ID_PATTERN
    )

    @field_validator("owner", "name")
    @classmethod
    def validate_git_component(cls, value: str) -> str:
        return GitValidator.validate_repository_component(value)
