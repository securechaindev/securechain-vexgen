from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class VEXBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    owner: str = Field(..., min_length=1, max_length=255)
    name: str = Field(..., min_length=1, max_length=255)
    sbom_path: str = Field(..., min_length=1)
    sbom_name: str | None = Field(None, max_length=255)
    moment: datetime | None = None


class VEXCreate(VEXBase):
    metadata: dict[str, Any] | None = None


class VEXResponse(VEXBase):
    id: str = Field(..., alias="_id")
    metadata: dict[str, Any] | None = None

    model_config = ConfigDict(
        populate_by_name=True,
        str_strip_whitespace=True
    )
