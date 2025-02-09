from pydantic import BaseModel, Field

from .statements_group import StatementsGroup


class GenerateVEXRequest(BaseModel):
    owner: str = Field(min_lengt=1)
    name: str = Field(min_lengt=1)
    sbom_path: str = Field(min_lengt=1)
    statements_group: StatementsGroup
    user_id: str
