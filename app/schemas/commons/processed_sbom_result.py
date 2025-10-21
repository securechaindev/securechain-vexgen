from typing import Any

from pydantic import BaseModel, Field


class ProcessedSBOMResult(BaseModel):
    vex_list: list[dict[str, Any]] = Field(...)
    tix_list: list[dict[str, Any]] = Field(...)
    sbom_paths: list[str] = Field(...)
    directory: str = Field(...)
