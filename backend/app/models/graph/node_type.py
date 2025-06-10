from enum import Enum


class NodeType(str, Enum):
    cargo_package = "CargoPackage"
    nuget_package = "NuGetPackage"
    pypi_package = "PyPIPackage"
    npm_package = "NPMPackage"
    maven_package = "MavenPackage"
