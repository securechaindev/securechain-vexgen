import pytest

from app.domain.vex_generation.parsers.node_type_mapper import NodeTypeMapper
from app.exceptions import ComponentNotSupportedException


class TestNodeTypeMapper:

    def test_get_extension_pypi(self):
        extension = NodeTypeMapper.get_extension("PyPIPackage")
        assert extension == ".py"

    def test_get_extension_npm(self):
        extension = NodeTypeMapper.get_extension("NPMPackage")
        assert extension == ".js"

    def test_get_extension_maven(self):
        extension = NodeTypeMapper.get_extension("MavenPackage")
        assert extension == ".java"

    def test_get_extension_cargo(self):
        extension = NodeTypeMapper.get_extension("CargoPackage")
        assert extension == ".rs"

    def test_get_extension_nuget(self):
        extension = NodeTypeMapper.get_extension("NuGetPackage")
        assert extension == ".cs"

    def test_get_extension_rubygems(self):
        extension = NodeTypeMapper.get_extension("RubyGemsPackage")
        assert extension == ".rb"

    def test_get_extension_unsupported(self):
        with pytest.raises(ComponentNotSupportedException):
            NodeTypeMapper.get_extension("UnsupportedPackage")

    def test_purl_type_to_node_type_pypi(self):
        node_type = NodeTypeMapper.purl_type_to_node_type("pypi")
        assert node_type == "PyPIPackage"

    def test_purl_type_to_node_type_npm(self):
        node_type = NodeTypeMapper.purl_type_to_node_type("npm")
        assert node_type == "NPMPackage"

    def test_purl_type_to_node_type_maven(self):
        node_type = NodeTypeMapper.purl_type_to_node_type("maven")
        assert node_type == "MavenPackage"

    def test_purl_type_to_node_type_cargo(self):
        node_type = NodeTypeMapper.purl_type_to_node_type("cargo")
        assert node_type == "CargoPackage"

    def test_purl_type_to_node_type_nuget(self):
        node_type = NodeTypeMapper.purl_type_to_node_type("nuget")
        assert node_type == "NuGetPackage"

    def test_purl_type_to_node_type_gem(self):
        node_type = NodeTypeMapper.purl_type_to_node_type("gem")
        assert node_type == "RubyGemsPackage"

    def test_purl_type_to_node_type_case_insensitive(self):
        node_type = NodeTypeMapper.purl_type_to_node_type("PYPI")
        assert node_type == "PyPIPackage"

    def test_purl_type_to_node_type_unsupported(self):
        with pytest.raises(ComponentNotSupportedException):
            NodeTypeMapper.purl_type_to_node_type("unsupported")

    def test_get_supported_node_types(self):
        node_types = NodeTypeMapper.get_supported_node_types()
        assert isinstance(node_types, list)
        assert len(node_types) == 6
        assert "PyPIPackage" in node_types
        assert "NPMPackage" in node_types
        assert "MavenPackage" in node_types
        assert "CargoPackage" in node_types
        assert "NuGetPackage" in node_types
        assert "RubyGemsPackage" in node_types

    def test_get_supported_purl_types(self):
        purl_types = NodeTypeMapper.get_supported_purl_types()
        assert isinstance(purl_types, list)
        assert len(purl_types) == 6
        assert "pypi" in purl_types
        assert "npm" in purl_types
        assert "maven" in purl_types
        assert "cargo" in purl_types
        assert "nuget" in purl_types
        assert "gem" in purl_types
