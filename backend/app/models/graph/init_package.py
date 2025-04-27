from pydantic import BaseModel, Field

from .node_type import NodeType


class InitPackageRequest(BaseModel):
    name: str  = Field(...)
    node_type: NodeType = Field(...)
