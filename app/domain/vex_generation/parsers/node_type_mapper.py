from typing import ClassVar

from app.exceptions import ComponentNotSupportedException


class NodeTypeMapper:
    EXTENSION_MAP: ClassVar[dict[str, str]] = {
        "PyPIPackage": ".py",
        "NPMPackage": ".js",
        "MavenPackage": ".java",
        "CargoPackage": ".rs",
        "NuGetPackage": ".cs",
        "RubyGemsPackage": ".rb"
    }

    PURL_TYPE_MAP: ClassVar[dict[str, str]] = {
        "pypi": "PyPIPackage",
        "npm": "NPMPackage",
        "maven": "MavenPackage",
        "cargo": "CargoPackage",
        "nuget": "NuGetPackage",
        "gem": "RubyGemsPackage"
    }

    @classmethod
    def get_extension(cls, node_type: str) -> str:
        extension = cls.EXTENSION_MAP.get(node_type)
        if extension is None:
            raise ComponentNotSupportedException()
        return extension

    @classmethod
    def purl_type_to_node_type(cls, purl_type: str) -> str:
        node_type = cls.PURL_TYPE_MAP.get(purl_type.lower())
        if node_type is None:
            raise ComponentNotSupportedException()
        return node_type

    @classmethod
    def get_supported_node_types(cls) -> list[str]:
        return list(cls.EXTENSION_MAP.keys())

    @classmethod
    def get_supported_purl_types(cls) -> list[str]:
        return list(cls.PURL_TYPE_MAP.keys())
