from app.exceptions import ComponentNotSupportedException
from app.schemas import NodeType


async def get_node_type(purl: str) -> str:
    if "pypi" in purl:
        return NodeType.pypi_package.value
    elif "npm" in purl:
        return NodeType.npm_package.value
    elif "cargo" in purl:
        return NodeType.cargo_package.value
    elif "nuget" in purl:
        return NodeType.nuget_package.value
    elif "maven" in purl:
        return NodeType.maven_package.value
    elif "gem" in purl:
        return NodeType.rubygems_package.value
    else:
        raise ComponentNotSupportedException()
