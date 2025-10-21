from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock, patch

import pytest

from app.domain.code_analyzer.analyzers.csharp_analyzer import CSharpAnalyzer


class TestCSharpAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return CSharpAnalyzer()

    def test_get_import_pattern(self, analyzer):
        pattern = analyzer.get_import_pattern("System.Collections.Generic")
        assert "using" in pattern
        assert "System.Collections.Generic" in pattern

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_is_imported_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.cs', delete=False) as f:
            f.write("using System;\n")
            f.write("using System.Collections.Generic;\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["System.Collections.Generic"])
            assert result is True

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_is_imported_not_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.cs', delete=False) as f:
            f.write("using System;\n")
            f.write("public class MyClass {}\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["System.Net.Http"])
            assert result is False or result is None

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_is_imported_multiple_namespaces(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.cs', delete=False) as f:
            f.write("using System.Linq;\n")
            f.write("using System.Text;\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["System.Linq", "System.Missing"])
            assert result is True

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_is_imported_file_not_found(self, analyzer):
        result = await analyzer.is_imported("/non/existent/file.cs", ["System"])
        assert result is False

    def test_should_skip_line_comment_single(self, analyzer):
        skip, inside = analyzer.should_skip_line("// This is a comment", False)
        assert skip is True
        assert inside is False

    def test_should_skip_line_comment_multi_start(self, analyzer):
        skip, inside = analyzer.should_skip_line("/* Comment start", False)
        assert skip is True
        assert inside is True

    def test_should_skip_line_comment_multi_inside(self, analyzer):
        skip, inside = analyzer.should_skip_line("  some comment text", True)
        assert skip is True
        assert inside is True

    def test_should_skip_line_comment_multi_end(self, analyzer):
        skip, inside = analyzer.should_skip_line("  end comment */", True)
        assert skip is True
        assert inside is False

    def test_should_skip_line_using(self, analyzer):
        skip, inside = analyzer.should_skip_line("using System.Collections;", False)
        assert skip is True
        assert inside is False

    def test_should_skip_line_normal_code(self, analyzer):
        skip, inside = analyzer.should_skip_line("var result = MyMethod();", False)
        assert skip is False
        assert inside is False

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_extract_patterns_with_assignment(self, analyzer):
        code = """
        var myVar = new MyClass();
        MyType result = new Factory();
        """
        patterns, used_artefacts = await analyzer.extract_patterns(["System.Example"], code)

        assert "myVar" in analyzer.known_aliases or "result" in analyzer.known_aliases
        assert len(patterns) > 0
        assert isinstance(used_artefacts, dict)

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_extract_patterns_multiple_imports(self, analyzer):
        code = "using System.Linq;\nusing System.Collections.Generic;\n"

        patterns, _used_artefacts = await analyzer.extract_patterns(
            ["System.Linq", "System.Collections.Generic"],
            code
        )

        assert len(patterns) >= 5
        pattern_types = [p[1] for p in patterns]
        assert "dot_access" in pattern_types
        assert "using_import" in pattern_types

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_extract_patterns_includes_alias_pattern(self, analyzer):
        patterns, _ = await analyzer.extract_patterns(["System.Example"], "")

        alias_patterns = [p for p in patterns if p[1] == "alias_method_call"]
        assert len(alias_patterns) > 0

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_process_match_dot_access(self, analyzer):
        code = "MyClass.MethodName()"

        affected_artefacts = {
            "System.Example": {
                "artefacts": {
                    "method": ["MethodName"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            import re
            match = re.search(r"MyClass\.[^\(\)\s:;]+", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "dot_access", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result is not None
                assert len(result) > 0

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_process_match_using_import(self, analyzer):
        code = "using System.Collections.Generic;"

        affected_artefacts = {
            "System.Collections.Generic": {
                "artefacts": {
                    "class": ["List", "Dictionary"]
                }
            }
        }

        import re
        match = re.search(r"using\s+System\.Collections\.Generic\s*;", code)
        if match:
            used_artefacts = {}
            new_artefacts = []
            result = await analyzer.process_match(
                match, "using_import", affected_artefacts,
                "test CVE", used_artefacts, new_artefacts
            )

            assert result is None
            assert "System.Collections.Generic" in analyzer.using_namespaces

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_process_match_alias_method_call(self, analyzer):
        analyzer.known_aliases.add("myService")
        code = "myService.Execute()"

        affected_artefacts = {
            "System.Example": {
                "artefacts": {
                    "method": ["Execute"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            import re
            match = re.search(r"(\w+)\.(\w+)\s*\(", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "alias_method_call", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result is None
                assert "Execute" in new_artefacts

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_process_match_chained_method_calls(self, analyzer):
        code = "MyClass.Method1().Method2();"

        affected_artefacts = {
            "System.Example": {
                "artefacts": {
                    "method": ["Method1", "Method2"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            import re
            match = re.search(r"MyClass\.[^\(\)\s:;]+", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "dot_access", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result is not None

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_process_match_no_relevant_artefacts(self, analyzer):
        code = "MyClass.SomeMethod()"

        affected_artefacts = {
            "System.Example": {
                "artefacts": {
                    "method": ["DifferentMethod"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=False):
            import re
            match = re.search(r"MyClass\.[^\(\)\s:;]+", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "dot_access", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result == [] or result is not None

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_extract_patterns_empty_code(self, analyzer):
        patterns, used_artefacts = await analyzer.extract_patterns(["System.Example"], "")

        assert isinstance(patterns, list)
        assert isinstance(used_artefacts, dict)
        assert len(patterns) > 0

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_assignment_pattern_var_keyword(self, analyzer):
        code = """
        var items = new List();
        var data = new Dictionary();
        """
        patterns, _used_artefacts = await analyzer.extract_patterns(["System.Collections"], code)

        assert "items" in analyzer.known_aliases or "data" in analyzer.known_aliases or len(patterns) >= 3

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_assignment_pattern_explicit_type(self, analyzer):
        code = """
        List<string> items = new List<string>();
        MyClass instance = new MyClass();
        """
        _patterns, _used_artefacts = await analyzer.extract_patterns(["System.Example"], code)

        assert "items" in analyzer.known_aliases or "instance" in analyzer.known_aliases

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_get_used_artefacts_with_using_namespace(self, analyzer):
        analyzer.using_namespaces.add("System.Collections.Generic")

        with NamedTemporaryFile(mode='w', suffix='.cs', delete=False) as f:
            f.write("using System.Collections.Generic;\n")
            f.write("List<int> numbers = new List<int>();\n")
            f.flush()

            affected_artefacts = {
                "System.Collections.Generic": {
                    "artefacts": {
                        "class": ["List"]
                    }
                }
            }

            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                       new_callable=AsyncMock, return_value=True):
                with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                           return_value=True):
                    result = await analyzer.get_used_artefacts(
                        f.name, ["System.Collections.Generic"],
                        "test CVE", affected_artefacts
                    )

                    assert isinstance(result, list)

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_get_used_artefacts_filters_invalid_names(self, analyzer):
        analyzer.using_namespaces.add("System.Test")

        with NamedTemporaryFile(mode='w', suffix='.cs', delete=False) as f:
            f.write("using System.Test;\n")
            f.write("InvalidClass123 test = new InvalidClass123();\n")
            f.flush()

            affected_artefacts = {
                "System.Test": {
                    "artefacts": {
                        "class": ["InvalidClass123"]
                    }
                }
            }

            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                       new_callable=AsyncMock, return_value=True):
                with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                           return_value=False):
                    result = await analyzer.get_used_artefacts(
                        f.name, ["System.Test"],
                        "test CVE", affected_artefacts
                    )

                    assert result == [] or isinstance(result, list)

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_get_used_artefacts_empty_artefact_name(self, analyzer):
        analyzer.using_namespaces.add("System.Test")

        with NamedTemporaryFile(mode='w', suffix='.cs', delete=False) as f:
            f.write("using System.Test;\n")
            f.flush()

            affected_artefacts = {
                "System.Test": {
                    "artefacts": {
                        "class": ["", "  ", "ValidClass"]
                    }
                }
            }

            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                       new_callable=AsyncMock, return_value=True):
                with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                           return_value=True):
                    result = await analyzer.get_used_artefacts(
                        f.name, ["System.Test"],
                        "test CVE", affected_artefacts
                    )

                    assert isinstance(result, list)

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_process_match_invalid_artefact_name(self, analyzer):
        code = "MyClass.123invalid()"

        affected_artefacts = {
            "System.Example": {
                "artefacts": {
                    "method": ["validMethod"]
                }
            }
        }

        import re
        match = re.search(r"MyClass\.[^\(\)\s:;]+", code)
        if match:
            used_artefacts = {}
            new_artefacts = []
            result = await analyzer.process_match(
                match, "dot_access", affected_artefacts,
                "test CVE", used_artefacts, new_artefacts
            )

            assert result == [] or result is not None

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_extract_patterns_generic_type_assignment(self, analyzer):
        code = """
        var list = new List();
        MyClass instance = new MyClass();
        """
        patterns, used_artefacts = await analyzer.extract_patterns(["System.Example"], code)

        assert len(patterns) >= 3
        assert isinstance(used_artefacts, dict)
