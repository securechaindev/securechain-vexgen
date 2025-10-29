from typing import ClassVar

from app.exceptions import ComponentNotSupportedException

from .analyzers import (
    BaseCodeAnalyzer,
    CSharpAnalyzer,
    JavaAnalyzer,
    JavaScriptTypeScriptAnalyzer,
    PythonAnalyzer,
    RubyAnalyzer,
    RustAnalyzer,
)


class CodeAnalyzerFactory:
    analyzers: ClassVar[dict[str, BaseCodeAnalyzer]] = {
        "PyPIPackage": PythonAnalyzer(),
        "NPMPackage": JavaScriptTypeScriptAnalyzer(),
        "MavenPackage": JavaAnalyzer(),
        "CargoPackage": RustAnalyzer(),
        "NuGetPackage": CSharpAnalyzer(),
        "RubyGemsPackage": RubyAnalyzer(),
    }

    @classmethod
    def get_analyzer(cls, node_type: str) -> BaseCodeAnalyzer:
        analyzer = cls.analyzers.get(node_type)
        if analyzer is None:
            raise ComponentNotSupportedException()
        return analyzer
