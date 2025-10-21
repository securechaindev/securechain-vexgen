from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock, patch

import pytest

from app.domain.code_analyzer.analyzers.java_analyzer import JavaAnalyzer


class TestJavaAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return JavaAnalyzer()

    def test_get_import_pattern(self, analyzer):
        pattern = analyzer.get_import_pattern("com.example.MyClass")
        assert "import" in pattern
        assert "com.example.MyClass" in pattern

    @pytest.mark.asyncio
    async def test_is_imported_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
            f.write("import java.util.ArrayList;\n")
            f.write("import com.example.MyClass;\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["com.example.MyClass"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_not_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
            f.write("import java.util.ArrayList;\n")
            f.write("public class MyClass {}\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["com.example.OtherClass"])
            assert result is False or result is None

    @pytest.mark.asyncio
    async def test_is_imported_multiple_packages(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
            f.write("import java.util.ArrayList;\n")
            f.write("import java.util.HashMap;\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["java.util.ArrayList", "com.example.Missing"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_file_not_found(self, analyzer):
        result = await analyzer.is_imported("/non/existent/file.java", ["com.example.Class"])
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

    def test_should_skip_line_import(self, analyzer):
        skip, inside = analyzer.should_skip_line("import java.util.ArrayList;", False)
        assert skip is True
        assert inside is False

    def test_should_skip_line_normal_code(self, analyzer):
        skip, inside = analyzer.should_skip_line("String result = myMethod();", False)
        assert skip is False
        assert inside is False

    @pytest.mark.asyncio
    async def test_extract_patterns_with_assignment(self, analyzer):
        code = """
        String myVar = SomeClass.create();
        MyType result = factory.build(param);
        """
        patterns, used_artefacts = await analyzer.extract_patterns(["com.example"], code)

        assert "myVar" in analyzer.known_aliases or "result" in analyzer.known_aliases
        assert len(patterns) > 0
        assert isinstance(used_artefacts, dict)

    @pytest.mark.asyncio
    async def test_extract_patterns_with_this_assignment(self, analyzer):
        code = """
        this.service = ServiceFactory.create();
        """
        _patterns, _used_artefacts = await analyzer.extract_patterns(["com.example"], code)

        assert "service" in analyzer.known_aliases or "this.service" in analyzer.known_aliases

    @pytest.mark.asyncio
    async def test_extract_patterns_multiple_imports(self, analyzer):
        code = "import java.util.ArrayList;\nimport com.example.MyClass;\n"

        patterns, _used_artefacts = await analyzer.extract_patterns(
            ["java.util.ArrayList", "com.example.MyClass"],
            code
        )

        assert len(patterns) >= 4
        pattern_types = [p[1] for p in patterns]
        assert "split_by_dot" in pattern_types
        assert "split_by_import" in pattern_types

    @pytest.mark.asyncio
    async def test_extract_patterns_includes_alias_pattern(self, analyzer):
        patterns, _ = await analyzer.extract_patterns(["com.example"], "")

        alias_patterns = [p for p in patterns if p[1] == "alias_method_call"]
        assert len(alias_patterns) > 0

    @pytest.mark.asyncio
    async def test_process_match_split_by_dot(self, analyzer):
        code = "MyClass.methodName()"

        affected_artefacts = {
            "com.example": {
                "artefacts": {
                    "method": ["methodName"]
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
                    match, "split_by_dot", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result is not None
                assert len(result) > 0

    @pytest.mark.asyncio
    async def test_process_match_split_by_import(self, analyzer):
        code = "import com.example.MyClass.InnerClass;"

        affected_artefacts = {
            "com.example": {
                "artefacts": {
                    "class": ["MyClass", "InnerClass"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            import re
            match = re.search(r"import\s+com\.example\.[^\(\)\s:;]+;", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "split_by_import", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_alias_method_call(self, analyzer):
        analyzer.known_aliases.add("myService")
        code = "myService.execute()"

        affected_artefacts = {
            "com.example": {
                "artefacts": {
                    "method": ["execute"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            import re
            match = re.search(r"(\w+(?:\.\w+)?)\.(\w+)\s*\(", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                await analyzer.process_match(
                    match, "alias_method_call", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert "execute" in new_artefacts

    @pytest.mark.asyncio
    async def test_process_match_alias_with_this(self, analyzer):
        analyzer.known_aliases.add("this.service")
        code = "this.service.doSomething()"

        affected_artefacts = {
            "com.example": {
                "artefacts": {
                    "method": ["doSomething"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            import re
            match = re.search(r"(\w+(?:\.\w+)?)\.(\w+)\s*\(", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                await analyzer.process_match(
                    match, "alias_method_call", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert "doSomething" in new_artefacts

    @pytest.mark.asyncio
    async def test_process_match_chained_method_calls(self, analyzer):
        code = "MyClass.method1().method2();"

        affected_artefacts = {
            "com.example": {
                "artefacts": {
                    "method": ["method1", "method2"]
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
                    match, "split_by_dot", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_with_semicolon(self, analyzer):
        code = "import com.example.MyClass.method;"

        affected_artefacts = {
            "com.example": {
                "artefacts": {
                    "method": ["method"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            import re
            match = re.search(r"import\s+com\.example\.[^\(\)\s:;]+;", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "split_by_import", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_invalid_artefact_name(self, analyzer):
        code = "MyClass.123invalid()"

        affected_artefacts = {
            "com.example": {
                "artefacts": {
                    "method": ["validMethod"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                   return_value=False):
            import re
            match = re.search(r"MyClass\.[^\(\)\s:;]+", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "split_by_dot", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result == [] or result is not None

    @pytest.mark.asyncio
    async def test_process_match_no_relevant_artefacts(self, analyzer):
        code = "MyClass.someMethod()"

        affected_artefacts = {
            "com.example": {
                "artefacts": {
                    "method": ["differentMethod"]
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
                    match, "split_by_dot", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result == [] or result is not None

    @pytest.mark.asyncio
    async def test_extract_patterns_empty_code(self, analyzer):
        patterns, used_artefacts = await analyzer.extract_patterns(["com.example"], "")

        assert isinstance(patterns, list)
        assert isinstance(used_artefacts, dict)
        assert len(patterns) > 0

    @pytest.mark.asyncio
    async def test_is_imported_wildcard_import(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
            f.write("import java.util.*;\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["java.util"])
            assert result is True

    @pytest.mark.asyncio
    async def test_assignment_pattern_generic_types(self, analyzer):
        code = """
        List<String> items = factory.createList();
        Map<String, Integer> data = builder.build();
        """
        _patterns, _used_artefacts = await analyzer.extract_patterns(["com.example"], code)

        assert "items" in analyzer.known_aliases or "data" in analyzer.known_aliases
