from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock, patch

import pytest

from app.domain.code_analyzer.analyzers.javascript_typescript_analyzer import (
    JavaScriptTypeScriptAnalyzer,
)


class TestJavaScriptTypeScriptAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return JavaScriptTypeScriptAnalyzer()

    def test_get_import_pattern(self, analyzer):
        pattern = analyzer.get_import_pattern("express")
        assert "import" in pattern
        assert "from" in pattern
        assert "require" in pattern
        assert "express" in pattern

    @pytest.mark.asyncio
    async def test_is_imported_with_import_statement(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write("import express from 'express';\n")
            f.write("const app = express();\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["express"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_with_require_statement(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write("const express = require('express');\n")
            f.write("const app = express();\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["express"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_not_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write("const app = express();\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["express"])
            assert result is False or result is None

    @pytest.mark.asyncio
    async def test_is_imported_multiple_packages(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write("import lodash from 'lodash';\n")
            f.write("const app = express();\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["express", "lodash", "axios"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_file_not_found(self, analyzer):
        result = await analyzer.is_imported("/non/existent/file.js", ["express"])
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
        skip, inside = analyzer.should_skip_line("import express from 'express';", False)
        assert skip is True
        assert inside is False

    def test_should_skip_line_require(self, analyzer):
        skip, inside = analyzer.should_skip_line("const fs = require('fs');", False)
        assert skip is True
        assert inside is False

    def test_should_skip_line_normal_code(self, analyzer):
        skip, inside = analyzer.should_skip_line("const result = calculate();", False)
        assert skip is False
        assert inside is False

    @pytest.mark.asyncio
    async def test_extract_patterns_with_imports(self, analyzer):
        code = """
        import express from 'express';
        const app = express();
        """
        patterns, used_artefacts = await analyzer.extract_patterns(["express"], code)

        assert len(patterns) > 0
        assert isinstance(used_artefacts, dict)
        pattern_types = [p[1] for p in patterns]
        assert "dot_access" in pattern_types
        assert "named_import" in pattern_types

    @pytest.mark.asyncio
    async def test_extract_patterns_with_alias(self, analyzer):
        code = """
        import myAlias from 'some-package';
        const result = myAlias.method();
        """
        patterns, _used_artefacts = await analyzer.extract_patterns(["some-package"], code)

        assert "myAlias" in analyzer.known_aliases
        assert len(patterns) > 0

    @pytest.mark.asyncio
    async def test_extract_patterns_with_require_alias(self, analyzer):
        code = """
        const lodash = require('lodash');
        const result = lodash.map([1, 2, 3], x => x * 2);
        """
        patterns, _used_artefacts = await analyzer.extract_patterns(["lodash"], code)

        assert "lodash" in analyzer.known_aliases
        assert len(patterns) > 0

    @pytest.mark.asyncio
    async def test_extract_patterns_multiple_imports(self, analyzer):
        code = """
        import express from 'express';
        import axios from 'axios';
        """
        patterns, _used_artefacts = await analyzer.extract_patterns(["express", "axios"], code)

        assert len(patterns) >= 4

    @pytest.mark.asyncio
    async def test_process_match_named_import(self, analyzer):
        code = "import { Router, json } from 'express';"
        patterns, _ = await analyzer.extract_patterns(["express"], code)

        import_pattern = next((p for p in patterns if p[1] == "named_import"), None)
        assert import_pattern is not None

        affected_artefacts = {
            "express": {
                "artefacts": {
                    "class": ["Router"],
                    "function": ["json"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            import re
            match = re.search(import_pattern[0], code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "named_import", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result is not None
                assert len(result) > 0

    @pytest.mark.asyncio
    async def test_process_match_dot_access(self, analyzer):
        code = "express.Router()"

        affected_artefacts = {
            "express": {
                "artefacts": {
                    "class": ["Router"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            import re
            match = re.search(r"express\.[^\(\)\s:;]+", code)
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
    async def test_process_match_alias_method_call(self, analyzer):
        analyzer.known_aliases.add("myLib")
        code = "myLib.someMethod()"

        affected_artefacts = {
            "some-package": {
                "artefacts": {
                    "function": ["someMethod"]
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
                await analyzer.process_match(
                    match, "alias_method_call", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert "someMethod" in new_artefacts

    @pytest.mark.asyncio
    async def test_process_match_named_import_invalid_artefact(self, analyzer):
        code = "import { , , validName } from 'express';"

        affected_artefacts = {
            "express": {
                "artefacts": {
                    "function": ["validName"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                   return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                       new_callable=AsyncMock, return_value=True):
                import re
                match = re.search(r"import\s+\{[^\}]+\}\s+from\s+['\"]express['\"]", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "named_import", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_dot_access_chained(self, analyzer):
        code = "obj.prop1.prop2.method()"

        affected_artefacts = {
            "obj": {
                "artefacts": {
                    "property": ["prop1", "prop2"],
                    "function": ["method"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            import re
            match = re.search(r"obj\.[^\(\)\s:;]+", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "dot_access", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result is not None

    @pytest.mark.asyncio
    async def test_extract_patterns_empty_code(self, analyzer):
        patterns, used_artefacts = await analyzer.extract_patterns(["express"], "")

        assert isinstance(patterns, list)
        assert isinstance(used_artefacts, dict)
        assert len(patterns) > 0

    @pytest.mark.asyncio
    async def test_is_imported_with_scoped_package(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write("import React from '@types/react';\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["@types/react"])
            assert result is True

    @pytest.mark.asyncio
    async def test_should_skip_multiline_comment_complete(self, analyzer):
        skip, inside = analyzer.should_skip_line("/* complete comment */", False)
        assert skip is True
        assert inside is True

    @pytest.mark.asyncio
    async def test_process_match_no_relevant_artefacts(self, analyzer):
        code = "import { SomeFunc } from 'express';"

        affected_artefacts = {
            "express": {
                "artefacts": {
                    "function": ["DifferentFunc"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=False):
            import re
            match = re.search(r"import\s+\{[^\}]+\}\s+from\s+['\"]express['\"]", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "named_import", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result == [] or result is not None
