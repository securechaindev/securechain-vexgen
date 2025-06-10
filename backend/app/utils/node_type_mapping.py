from app.models.graph import NodeType

string_to_nodetype = {
    "pypi": NodeType.pypi_package,
    "npm": NodeType.npm_package,
    "cargo": NodeType.cargo_package,
    "nuget": NodeType.nuget_package,
    "maven": NodeType.maven_package,
}

def get_node_type(package_manager: str) -> NodeType:
    return string_to_nodetype[package_manager.lower()]
