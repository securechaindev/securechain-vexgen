from pydantic import BaseModel, Field


class DownloadVEXTIXRequest(BaseModel):
    vex_id: str = Field(min_length=1)
    tix_id: str = Field(min_length=1)


class GenerateVEXTIXRequest(BaseModel):
    owner: str = Field(min_lengt=1)
    name: str = Field(min_length=1)
    user_id: str
