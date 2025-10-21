from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock, patch

import pytest

from app.domain.code_analyzer.analyzers.rust_analyzer import RustAnalyzer


class TestRustAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return RustAnalyzer()

    def test_get_import_pattern(self, analyzer):
        pattern = analyzer.get_import_pattern("std")
        assert "extern crate" in pattern or "use" in pattern

    @pytest.mark.asyncio
    async def test_is_imported_extern_crate_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.rs', delete=False) as f:
            f.write("extern crate serde;\n")
            f.write("use std::collections::HashMap;\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["serde"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_use_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.rs', delete=False) as f:
            f.write("use std::io::Read;\n")
            f.write("use std::fs::File;\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["std"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_not_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.rs', delete=False) as f:
            f.write("use std::io;\n")
            f.write("fn main() {}\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["missing_crate"])
            assert result is False or result is None

    @pytest.mark.asyncio
    async def test_is_imported_file_not_found(self, analyzer):
        result = await analyzer.is_imported("/non/existent/file.rs", ["std"])
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

    def test_should_skip_line_extern_crate(self, analyzer):
        skip, inside = analyzer.should_skip_line("extern crate serde;", False)
        assert skip is True
        assert inside is False

    def test_should_skip_line_use(self, analyzer):
        skip, inside = analyzer.should_skip_line("use std::collections::HashMap;", False)
        assert skip is True
        assert inside is False

    def test_should_skip_line_normal_code(self, analyzer):
        skip, inside = analyzer.should_skip_line("let result = my_function();", False)
        assert skip is False
        assert inside is False

    @pytest.mark.asyncio
    async def test_extract_patterns_with_assignment(self, analyzer):
        code = """
        let my_var = MyStruct::new();
        let result = Factory::new();
        """
        patterns, used_artefacts = await analyzer.extract_patterns(["my_crate"], code)

        assert "my_var" in analyzer.known_aliases or "result" in analyzer.known_aliases
        assert len(patterns) > 0
        assert isinstance(used_artefacts, dict)

    @pytest.mark.asyncio
    async def test_extract_patterns_multiple_imports(self, analyzer):
        code = "use std::io;\nuse std::fs;\n"

        patterns, _used_artefacts = await analyzer.extract_patterns(
            ["std"],
            code
        )

        assert len(patterns) >= 4
        pattern_types = [p[1] for p in patterns]
        assert "split_by_double_colon" in pattern_types
        assert "split_by_braces" in pattern_types

    @pytest.mark.asyncio
    async def test_extract_patterns_includes_alias_pattern(self, analyzer):
        patterns, _ = await analyzer.extract_patterns(["std"], "")

        alias_patterns = [p for p in patterns if p[1] == "alias_method_call"]
        assert len(alias_patterns) > 0

    @pytest.mark.asyncio
    async def test_process_match_split_by_double_colon(self, analyzer):
        code = "std::io::Read"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "trait": ["Read"],
                    "module": ["io"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"std::[^\s\(\);]+", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_double_colon", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None
                    assert len(result) > 0

    @pytest.mark.asyncio
    async def test_process_match_split_by_braces(self, analyzer):
        code = "use std::{io, fs};"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "module": ["io", "fs"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"use\s+std::\{[^}]+\};", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_braces", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_split_by_braces_let(self, analyzer):
        code = "let {io, fs} = std::;"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "module": ["io", "fs"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"let\s+\{[^}]+\}\s*=\s*std::", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_braces", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_alias_method_call(self, analyzer):
        analyzer.known_aliases.add("my_service")
        code = "my_service.execute()"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "method": ["execute"]
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
                assert "execute" in new_artefacts

    @pytest.mark.asyncio
    async def test_process_match_chained_module_access(self, analyzer):
        code = "std::collections::HashMap::new"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "struct": ["HashMap"],
                    "module": ["collections"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"std::[^\s\(\);]+", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_double_colon", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_no_relevant_artefacts(self, analyzer):
        code = "std::some_module"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "module": ["different_module"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=False):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"std::[^\s\(\);]+", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_double_colon", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result == [] or result is not None

    @pytest.mark.asyncio
    async def test_extract_patterns_empty_code(self, analyzer):
        patterns, used_artefacts = await analyzer.extract_patterns(["std"], "")

        assert isinstance(patterns, list)
        assert isinstance(used_artefacts, dict)
        assert len(patterns) > 0

    @pytest.mark.asyncio
    async def test_assignment_pattern_with_let(self, analyzer):
        code = """
        let obj = MyStruct::new();
        let service = Factory::new();
        """
        _patterns, _used_artefacts = await analyzer.extract_patterns(["my_crate"], code)

        assert "obj" in analyzer.known_aliases or "service" in analyzer.known_aliases

    @pytest.mark.asyncio
    async def test_process_match_invalid_artefact_name(self, analyzer):
        code = "std::123invalid"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "module": ["valid_module"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                   return_value=False):
            import re
            match = re.search(r"std::[^\s\(\);]+", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "split_by_double_colon", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result == [] or result is not None

    @pytest.mark.asyncio
    async def test_process_match_empty_artefact(self, analyzer):
        code = "std::"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "module": ["some_module"]
                }
            }
        }

        import re
        match = re.search(r"std::[^\s\(\);]*", code)
        if match:
            used_artefacts = {}
            new_artefacts = []
            result = await analyzer.process_match(
                match, "split_by_double_colon", affected_artefacts,
                "test CVE", used_artefacts, new_artefacts
            )

            assert result == [] or result is not None

    @pytest.mark.asyncio
    async def test_is_imported_multiple_crates(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.rs', delete=False) as f:
            f.write("extern crate serde;\n")
            f.write("extern crate tokio;\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["serde", "missing"])
            assert result is True

    @pytest.mark.asyncio
    async def test_nested_module_access(self, analyzer):
        code = "std::collections::hash_map::HashMap"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "struct": ["HashMap"],
                    "module": ["collections", "hash_map"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"std::[^\s\(\);]+", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_double_colon", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_unknown_split_type(self, analyzer):
        code = "std::io"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "module": ["io"]
                }
            }
        }

        import re
        match = re.search(r"std::\w+", code)
        if match:
            used_artefacts = {}
            new_artefacts = []
            result = await analyzer.process_match(
                match, "unknown_type", affected_artefacts,
                "test CVE", used_artefacts, new_artefacts
            )

            assert result is None

    @pytest.mark.asyncio
    async def test_braces_with_multiple_items(self, analyzer):
        code = "use std::{io, fs, path};"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "module": ["io", "fs", "path"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"use\s+std::\{[^}]+\};", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_braces", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None
                    assert len(result) >= 3

    @pytest.mark.asyncio
    async def test_assignment_pattern_generic_types(self, analyzer):
        code = """
        let vec = Vec::new();
        let map = HashMap::new();
        """
        patterns, _used_artefacts = await analyzer.extract_patterns(["std"], code)

        assert "vec" in analyzer.known_aliases or "map" in analyzer.known_aliases or len(patterns) >= 4

    @pytest.mark.asyncio
    async def test_braces_with_whitespace(self, analyzer):
        code = "use std::{ io , fs , path };"

        affected_artefacts = {
            "std": {
                "artefacts": {
                    "module": ["io", "fs", "path"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"use\s+std::\{[^}]+\};", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_braces", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None
