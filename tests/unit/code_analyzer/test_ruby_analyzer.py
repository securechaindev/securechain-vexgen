from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock, patch

import pytest

from app.domain.code_analyzer.analyzers.ruby_analyzer import RubyAnalyzer


class TestRubyAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return RubyAnalyzer()

    def test_get_import_pattern(self, analyzer):
        pattern = analyzer.get_import_pattern("my_module")
        assert any(keyword in pattern for keyword in ["require", "include", "extend"])

    @pytest.mark.asyncio
    async def test_is_imported_require_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.rb', delete=False) as f:
            f.write("require 'json'\n")
            f.write("require 'my_module'\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["my_module"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_require_relative_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.rb', delete=False) as f:
            f.write("require_relative 'utils/helper'\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["utils/helper"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_include_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.rb', delete=False) as f:
            f.write("include MyModule\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["MyModule"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_extend_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.rb', delete=False) as f:
            f.write("extend AnotherModule\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["AnotherModule"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_not_found(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.rb', delete=False) as f:
            f.write("require 'json'\n")
            f.write("class MyClass; end\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["missing_module"])
            assert result is False or result is None

    @pytest.mark.asyncio
    async def test_is_imported_file_not_found(self, analyzer):
        result = await analyzer.is_imported("/non/existent/file.rb", ["my_module"])
        assert result is False

    def test_should_skip_line_comment(self, analyzer):
        skip, _inside = analyzer.should_skip_line("# This is a comment", False)
        assert skip is True

    def test_should_skip_line_require(self, analyzer):
        skip, _inside = analyzer.should_skip_line("require 'json'", False)
        assert skip is True

    def test_should_skip_line_require_relative(self, analyzer):
        skip, _inside = analyzer.should_skip_line("require_relative 'helper'", False)
        assert skip is True

    def test_should_skip_line_include(self, analyzer):
        skip, _inside = analyzer.should_skip_line("include MyModule", False)
        assert skip is True

    def test_should_skip_line_extend(self, analyzer):
        skip, _inside = analyzer.should_skip_line("extend AnotherModule", False)
        assert skip is True

    def test_should_skip_line_normal_code(self, analyzer):
        skip, _inside = analyzer.should_skip_line("result = my_method()", False)
        assert skip is False

    @pytest.mark.asyncio
    async def test_extract_patterns_with_assignment(self, analyzer):
        code = """
        my_var = MyClass.new
        result = Factory.new
        """
        patterns, used_artefacts = await analyzer.extract_patterns(["MyModule"], code)

        assert "my_var" in analyzer.known_aliases or "result" in analyzer.known_aliases
        assert len(patterns) > 0
        assert isinstance(used_artefacts, dict)

    @pytest.mark.asyncio
    async def test_extract_patterns_multiple_imports(self, analyzer):
        code = "require 'json'\nrequire 'my_module'\n"

        patterns, _used_artefacts = await analyzer.extract_patterns(
            ["json", "my_module"],
            code
        )

        assert len(patterns) >= 13
        pattern_types = [p[1] for p in patterns]
        assert "split_by_double_colon" in pattern_types
        assert "split_by_dot" in pattern_types
        assert "split_by_slash" in pattern_types

    @pytest.mark.asyncio
    async def test_extract_patterns_includes_alias_pattern(self, analyzer):
        patterns, _ = await analyzer.extract_patterns(["MyModule"], "")

        alias_patterns = [p for p in patterns if p[1] == "alias_method_call"]
        assert len(alias_patterns) > 0

    @pytest.mark.asyncio
    async def test_process_match_split_by_double_colon(self, analyzer):
        code = "MyModule::MyClass::method_name"

        affected_artefacts = {
            "MyModule": {
                "artefacts": {
                    "method": ["method_name"],
                    "class": ["MyClass"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"MyModule::[^\s\(\)\.:;]+", code)
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
    async def test_process_match_split_by_dot(self, analyzer):
        code = "MyModule.method_name"

        affected_artefacts = {
            "MyModule": {
                "artefacts": {
                    "method": ["method_name"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"MyModule\.[^\s\(\)\.:;]+", code)
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
    async def test_process_match_split_by_slash(self, analyzer):
        code = "require 'my_module/utils/helper'"

        affected_artefacts = {
            "my_module": {
                "artefacts": {
                    "class": ["helper"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"require\s+['\"]([^/]+/[^'\"]+)['\"]", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_slash", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_split_by_double_colon_include(self, analyzer):
        code = "include MyModule::MyClass"

        affected_artefacts = {
            "MyModule": {
                "artefacts": {
                    "class": ["MyClass"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"include\s+MyModule::[^\s\(\)\.:;]+", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_double_colon_include", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_split_by_double_colon_extend(self, analyzer):
        code = "extend MyModule::MyMixin"

        affected_artefacts = {
            "MyModule": {
                "artefacts": {
                    "module": ["MyMixin"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"extend\s+MyModule::[^\s\(\)\.:;]+", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_double_colon_extend", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_alias_method_call(self, analyzer):
        analyzer.known_aliases.add("my_service")
        code = "my_service.execute"

        affected_artefacts = {
            "MyModule": {
                "artefacts": {
                    "method": ["execute"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            import re
            match = re.search(r"(\w+)\.(\w+)", code)
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
    async def test_process_match_chained_method_calls(self, analyzer):
        code = "MyModule.method1.method2"

        affected_artefacts = {
            "MyModule": {
                "artefacts": {
                    "method": ["method1", "method2"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"MyModule\.[^\s\(\)\.:;]+", code)
                if match:
                    used_artefacts = {}
                    new_artefacts = []
                    result = await analyzer.process_match(
                        match, "split_by_dot", affected_artefacts,
                        "test CVE", used_artefacts, new_artefacts
                    )

                    assert result is not None

    @pytest.mark.asyncio
    async def test_process_match_no_relevant_artefacts(self, analyzer):
        code = "MyModule.some_method"

        affected_artefacts = {
            "MyModule": {
                "artefacts": {
                    "method": ["different_method"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=False):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"MyModule\.[^\s\(\)\.:;]+", code)
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
        patterns, used_artefacts = await analyzer.extract_patterns(["MyModule"], "")

        assert isinstance(patterns, list)
        assert isinstance(used_artefacts, dict)
        assert len(patterns) > 0

    @pytest.mark.asyncio
    async def test_assignment_pattern_simple(self, analyzer):
        code = """
        obj = MyClass.new
        service = Factory.new
        """
        _patterns, _used_artefacts = await analyzer.extract_patterns(["MyModule"], code)

        assert "obj" in analyzer.known_aliases or "service" in analyzer.known_aliases

    @pytest.mark.asyncio
    async def test_process_match_invalid_artefact_name(self, analyzer):
        code = "MyModule.123invalid"

        affected_artefacts = {
            "MyModule": {
                "artefacts": {
                    "method": ["valid_method"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                   return_value=False):
            import re
            match = re.search(r"MyModule\.[^\s\(\)\.:;]+", code)
            if match:
                used_artefacts = {}
                new_artefacts = []
                result = await analyzer.process_match(
                    match, "split_by_dot", affected_artefacts,
                    "test CVE", used_artefacts, new_artefacts
                )

                assert result == [] or result is not None

    @pytest.mark.asyncio
    async def test_process_match_empty_artefact(self, analyzer):
        code = "MyModule."

        affected_artefacts = {
            "MyModule": {
                "artefacts": {
                    "method": ["some_method"]
                }
            }
        }

        import re
        match = re.search(r"MyModule\.[^\s\(\)\.:;]*", code)
        if match:
            used_artefacts = {}
            new_artefacts = []
            result = await analyzer.process_match(
                match, "split_by_dot", affected_artefacts,
                "test CVE", used_artefacts, new_artefacts
            )

            assert result == [] or result is not None

    @pytest.mark.asyncio
    async def test_is_imported_with_quotes(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.rb', delete=False) as f:
            f.write("require 'my_module'\n")
            f.flush()

            result = await analyzer.is_imported(f.name, ["my_module"])
            assert result is True

    @pytest.mark.asyncio
    async def test_is_imported_with_double_quotes(self, analyzer):
        with NamedTemporaryFile(mode='w', suffix='.rb', delete=False) as f:
            f.write('require "my_module"\n')
            f.flush()

            result = await analyzer.is_imported(f.name, ["my_module"])
            assert result is True

    @pytest.mark.asyncio
    async def test_nested_module_access(self, analyzer):
        code = "MyModule::SubModule::MyClass"

        affected_artefacts = {
            "MyModule": {
                "artefacts": {
                    "module": ["SubModule"],
                    "class": ["MyClass"]
                }
            }
        }

        with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_relevant',
                   new_callable=AsyncMock, return_value=True):
            with patch('app.domain.code_analyzer.analyzers.code_validator.CodeValidator.is_valid_artefact_name',
                       return_value=True):
                import re
                match = re.search(r"MyModule::[^\s\(\)\.:;]+", code)
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
        code = "MyModule.method"

        affected_artefacts = {
            "MyModule": {
                "artefacts": {
                    "method": ["method"]
                }
            }
        }

        import re
        match = re.search(r"MyModule\.\w+", code)
        if match:
            used_artefacts = {}
            new_artefacts = []
            result = await analyzer.process_match(
                match, "unknown_type", affected_artefacts,
                "test CVE", used_artefacts, new_artefacts
            )

            assert result is None
