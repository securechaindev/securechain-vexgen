from app.schemas import NodeType


class TestNodeType:
    def test_cargo_package_value(self):
        assert NodeType.cargo_package.value == "CargoPackage"

    def test_nuget_package_value(self):
        assert NodeType.nuget_package.value == "NuGetPackage"

    def test_pypi_package_value(self):
        assert NodeType.pypi_package.value == "PyPIPackage"

    def test_npm_package_value(self):
        assert NodeType.npm_package.value == "NPMPackage"

    def test_maven_package_value(self):
        assert NodeType.maven_package.value == "MavenPackage"

    def test_rubygems_package_value(self):
        assert NodeType.rubygems_package.value == "RubyGemsPackage"

    def test_all_members(self):
        expected = {
            "cargo_package",
            "nuget_package",
            "pypi_package",
            "npm_package",
            "maven_package",
            "rubygems_package"
        }
        assert set(NodeType.__members__.keys()) == expected

    def test_enum_is_string(self):
        assert isinstance(NodeType.cargo_package, str)
        assert isinstance(NodeType.pypi_package, str)

    def test_comparison(self):
        assert NodeType.cargo_package == "CargoPackage"
        assert NodeType.pypi_package == "PyPIPackage"

    def test_iteration(self):
        node_types = list(NodeType)
        assert len(node_types) == 6
        assert NodeType.cargo_package in node_types
