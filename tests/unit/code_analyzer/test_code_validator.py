import pytest

from app.domain.code_analyzer.analyzers.code_validator import CodeValidator


class TestCodeValidator:
    @pytest.mark.asyncio
    async def test_is_relevant_artefact_in_list(self):
        result = await CodeValidator.is_relevant(
            "MyClass",
            ["MyClass", "OtherClass"],
            "Some CVE description"
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_is_relevant_artefact_in_description(self):
        result = await CodeValidator.is_relevant(
            "execute",
            ["different_method"],
            "The execute method allows remote code execution"
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_is_relevant_case_insensitive_description(self):
        result = await CodeValidator.is_relevant(
            "MyClass",
            [],
            "This affects myclass in version 1.0"
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_is_relevant_not_found(self):
        result = await CodeValidator.is_relevant(
            "NonExistent",
            ["MyClass", "OtherClass"],
            "Some unrelated CVE description"
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_is_relevant_empty_artefacts_list(self):
        result = await CodeValidator.is_relevant(
            "test",
            [],
            "This mentions test in description"
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_is_relevant_empty_description(self):
        result = await CodeValidator.is_relevant(
            "MyClass",
            ["MyClass"],
            ""
        )
        assert result is True

    def test_is_valid_artefact_name_valid(self):
        valid_names = [
            "MyClass",
            "my_method",
            "MyMethod123",
            "method_123",
            "Class2Test",
            "get_value",
            "setValue"
        ]

        for name in valid_names:
            assert CodeValidator.is_valid_artefact_name(name) is True

    def test_is_valid_artefact_name_invalid_too_short(self):
        assert CodeValidator.is_valid_artefact_name("a") is False
        assert CodeValidator.is_valid_artefact_name("") is False

    def test_is_valid_artefact_name_invalid_whitespace_only(self):
        assert CodeValidator.is_valid_artefact_name("  ") is False
        assert CodeValidator.is_valid_artefact_name("\t") is False

    def test_is_valid_artefact_name_invalid_symbols_only(self):
        invalid_symbols = ['"', "'", '!', '@', '#', '$', '%', '^', '&', '*']

        for symbol in invalid_symbols:
            assert CodeValidator.is_valid_artefact_name(symbol) is False

    def test_is_valid_artefact_name_no_alphanumeric(self):
        assert CodeValidator.is_valid_artefact_name("!!!") is False
        assert CodeValidator.is_valid_artefact_name("@@@") is False

    def test_is_valid_artefact_name_too_many_symbols(self):
        assert CodeValidator.is_valid_artefact_name("a!!!") is False
        assert CodeValidator.is_valid_artefact_name("ab!!!!") is False

    def test_is_valid_artefact_name_with_underscores(self):
        assert CodeValidator.is_valid_artefact_name("my_method_name") is True
        assert CodeValidator.is_valid_artefact_name("test_123") is True

    def test_is_valid_artefact_name_with_mixed_case(self):
        assert CodeValidator.is_valid_artefact_name("MyClassName") is True
        assert CodeValidator.is_valid_artefact_name("methodName") is True

    def test_is_valid_artefact_name_with_numbers(self):
        assert CodeValidator.is_valid_artefact_name("test123") is True
        assert CodeValidator.is_valid_artefact_name("123test") is True
        assert CodeValidator.is_valid_artefact_name("test1test2") is True

    def test_is_valid_artefact_name_exactly_50_percent_alphanumeric(self):
        assert CodeValidator.is_valid_artefact_name("ab!!") is True

    def test_is_valid_artefact_name_with_trailing_whitespace(self):
        assert CodeValidator.is_valid_artefact_name("  MyClass  ") is True
        assert CodeValidator.is_valid_artefact_name("\tmethod\t") is True

    @pytest.mark.asyncio
    async def test_is_relevant_partial_match_in_description(self):
        result = await CodeValidator.is_relevant(
            "read",
            [],
            "The readFile method is vulnerable"
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_is_relevant_both_conditions_true(self):
        result = await CodeValidator.is_relevant(
            "vulnerable_method",
            ["vulnerable_method", "other_method"],
            "The vulnerable_method allows injection"
        )
        assert result is True

    def test_is_valid_artefact_name_none(self):
        assert CodeValidator.is_valid_artefact_name(None) is False

    def test_is_valid_artefact_name_single_character_with_symbol(self):
        assert CodeValidator.is_valid_artefact_name("a!") is True
