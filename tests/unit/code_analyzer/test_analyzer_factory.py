import pytest

from app.domain.code_analyzer.analyzer_factory import CodeAnalyzerFactory
from app.domain.code_analyzer.analyzers import (
    CSharpAnalyzer,
    JavaAnalyzer,
    JavaScriptTypeScriptAnalyzer,
    PythonAnalyzer,
    RubyAnalyzer,
    RustAnalyzer,
)
from app.exceptions import ComponentNotSupportedException


class TestCodeAnalyzerFactory:

    def test_get_analyzer_pypi(self):
        analyzer = CodeAnalyzerFactory.get_analyzer("PyPIPackage")
        assert isinstance(analyzer, PythonAnalyzer)

    def test_get_analyzer_npm(self):
        analyzer = CodeAnalyzerFactory.get_analyzer("NPMPackage")
        assert isinstance(analyzer, JavaScriptTypeScriptAnalyzer)

    def test_get_analyzer_maven(self):
        analyzer = CodeAnalyzerFactory.get_analyzer("MavenPackage")
        assert isinstance(analyzer, JavaAnalyzer)

    def test_get_analyzer_cargo(self):
        analyzer = CodeAnalyzerFactory.get_analyzer("CargoPackage")
        assert isinstance(analyzer, RustAnalyzer)

    def test_get_analyzer_nuget(self):
        analyzer = CodeAnalyzerFactory.get_analyzer("NuGetPackage")
        assert isinstance(analyzer, CSharpAnalyzer)

    def test_get_analyzer_rubygems(self):
        analyzer = CodeAnalyzerFactory.get_analyzer("RubyGemsPackage")
        assert isinstance(analyzer, RubyAnalyzer)

    def test_get_analyzer_unsupported(self):
        with pytest.raises(ComponentNotSupportedException):
            CodeAnalyzerFactory.get_analyzer("UnsupportedPackage")

    def test_get_analyzer_empty_string(self):
        with pytest.raises(ComponentNotSupportedException):
            CodeAnalyzerFactory.get_analyzer("")

    def test_get_analyzer_returns_same_instance(self):
        analyzer1 = CodeAnalyzerFactory.get_analyzer("PyPIPackage")
        analyzer2 = CodeAnalyzerFactory.get_analyzer("PyPIPackage")
        assert analyzer1 is analyzer2

    def test_all_analyzers_available(self):
        analyzers = CodeAnalyzerFactory.analyzers
        assert len(analyzers) == 6
        assert "PyPIPackage" in analyzers
        assert "NPMPackage" in analyzers
        assert "MavenPackage" in analyzers
        assert "CargoPackage" in analyzers
        assert "NuGetPackage" in analyzers
        assert "RubyGemsPackage" in analyzers
