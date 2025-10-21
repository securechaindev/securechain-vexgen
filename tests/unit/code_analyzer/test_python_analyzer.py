from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from app.domain.code_analyzer.analyzers.python_analyzer import PythonAnalyzer


class TestPythonAnalyzer:

    @pytest.fixture
    def analyzer(self):
        return PythonAnalyzer()

    def test_get_import_pattern(self, analyzer):
        pattern = analyzer.get_import_pattern("requests")
        assert "requests" in pattern
        assert "from|import" in pattern

    @pytest.mark.asyncio
    async def test_is_imported_with_import_statement(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import requests\n")
            f.write("import json\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["requests"])
            Path(f.name).unlink()

        assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_with_from_import(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("from requests import get\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["requests"])
            Path(f.name).unlink()

        assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_not_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import json\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["requests"])
            Path(f.name).unlink()

        assert result is False or result is None

    @pytest.mark.asyncio
    async def test_is_imported_file_not_exists(self, analyzer):
        result = await analyzer.is_imported("/nonexistent/file.py", ["requests"])
        assert result is False

    def test_should_skip_line_comment(self, analyzer):
        should_skip, inside_comment = analyzer.should_skip_line("# This is a comment", False)
        assert should_skip is True
        assert inside_comment is False

    def test_should_skip_line_import(self, analyzer):
        should_skip, _inside_comment = analyzer.should_skip_line("import requests", False)
        assert should_skip is True

    def test_should_skip_line_normal_code(self, analyzer):
        should_skip, _inside_comment = analyzer.should_skip_line("x = 10", False)
        assert should_skip is False

    @pytest.mark.asyncio
    async def test_extract_patterns_basic(self, analyzer):
        code = "requests.get('http://example.com')"
        patterns, used_artefacts = await analyzer.extract_patterns(["requests"], code)

        assert len(patterns) > 0
        assert isinstance(used_artefacts, dict)

    @pytest.mark.asyncio
    async def test_extract_patterns_with_assignment(self, analyzer):
        code = "session = requests.Session()\nsession.get('http://example.com')"
        patterns, used_artefacts = await analyzer.extract_patterns(["requests"], code)

        assert len(patterns) > 0
        assert isinstance(used_artefacts, dict)

    @pytest.mark.asyncio
    async def test_process_match_from_module_import(self, analyzer):
        code = "from requests import get, post"
        _patterns, _ = await analyzer.extract_patterns(["requests"], code)

        from regex import compile
        pattern = compile(r"from\s+requests\s+import\s+[\w,\s]+")
        match = pattern.search(code)

        affected = {
            "requests": {
                "artefacts": {
                    "function": ["get", "post"]
                }
            }
        }
        used_artefacts = {}
        new_artefacts = []

        result = await analyzer.process_match(
            match, "from_module_import", affected, "", used_artefacts, new_artefacts
        )

        assert result is not None
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_process_match_dot_access(self, analyzer):
        code = "requests.get.something"
        _patterns, _ = await analyzer.extract_patterns(["requests"], code)

        from regex import compile
        pattern = compile(r"requests\.[^\(\)\s:]+")
        match = pattern.search(code)

        affected = {
            "requests": {
                "artefacts": {
                    "function": ["get"]
                }
            }
        }
        used_artefacts = {}
        new_artefacts = []

        result = await analyzer.process_match(
            match, "dot_access", affected, "", used_artefacts, new_artefacts
        )

        assert result is not None

    @pytest.mark.asyncio
    async def test_get_used_artefacts_basic(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import requests\n")
            f.write("requests.get('http://example.com')\n")
            f.flush()

            affected = {
                "requests": {
                    "artefacts": {
                        "function": ["get"]
                    }
                }
            }

            result = await analyzer.get_used_artefacts(
                f.name,
                ["requests"],
                "CVE description",
                affected
            )
            Path(f.name).unlink()

        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_get_used_artefacts_empty_file(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("")
            f.flush()

            result = await analyzer.get_used_artefacts(
                f.name,
                ["requests"],
                "",
                {}
            )
            Path(f.name).unlink()

        assert result == []
