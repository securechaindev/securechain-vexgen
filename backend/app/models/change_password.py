from pydantic import BaseModel, Field, validator

from .patterns import EMAIL_PATTERN
from .validators import validate_password


class ChangePasswordRequest(BaseModel):
    email: str = Field(pattern=EMAIL_PATTERN)
    old_password: str = Field(...)
    new_password: str = Field(...)

    @validator("new_password", "old_password")
    def validate_password(cls, value):
        return validate_password(value)
