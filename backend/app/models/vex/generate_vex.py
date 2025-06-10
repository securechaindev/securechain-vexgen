from pydantic import BaseModel, Field


class GenerateVEXRequest(BaseModel):
    owner: str = Field(min_lengt=1)
    name: str = Field(min_lengt=1)
    user_id: str
