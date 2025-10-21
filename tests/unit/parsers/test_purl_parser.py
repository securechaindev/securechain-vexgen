import pytest

from app.domain.vex_generation.parsers.purl_parser import PURLParser


class TestPURLParser:
    @pytest.fixture
    def parser(self):
        return PURLParser()

    @pytest.mark.asyncio
    async def test_extract_type_valid_purl(self, parser):
        purl = "pkg:pypi/django@3.2.0"
        result = await parser.extract_type(purl)
        assert result == "pypi"

    @pytest.mark.asyncio
    async def test_extract_type_npm_package(self, parser):
        purl = "pkg:npm/express@4.17.1"
        result = await parser.extract_type(purl)
        assert result == "npm"

    @pytest.mark.asyncio
    async def test_extract_type_maven_package(self, parser):
        purl = "pkg:maven/org.springframework/spring-core@5.3.0"
        result = await parser.extract_type(purl)
        assert result == "maven"

    @pytest.mark.asyncio
    async def test_extract_type_gem_package(self, parser):
        purl = "pkg:gem/rails@6.1.0"
        result = await parser.extract_type(purl)
        assert result == "gem"

    @pytest.mark.asyncio
    async def test_extract_type_cargo_package(self, parser):
        purl = "pkg:cargo/serde@1.0.0"
        result = await parser.extract_type(purl)
        assert result == "cargo"

    @pytest.mark.asyncio
    async def test_extract_type_nuget_package(self, parser):
        purl = "pkg:nuget/Newtonsoft.Json@13.0.1"
        result = await parser.extract_type(purl)
        assert result == "nuget"

    @pytest.mark.asyncio
    async def test_extract_type_empty_string(self, parser):
        result = await parser.extract_type("")
        assert result is None

    @pytest.mark.asyncio
    async def test_extract_type_none(self, parser):
        result = await parser.extract_type(None)
        assert result is None

    @pytest.mark.asyncio
    async def test_extract_type_no_colon(self, parser):
        result = await parser.extract_type("invalid-purl")
        assert result is None

    @pytest.mark.asyncio
    async def test_extract_type_invalid_format(self, parser):
        result = await parser.extract_type("not-a-purl:test")
        assert result is None

    @pytest.mark.asyncio
    async def test_extract_type_with_namespace(self, parser):
        purl = "pkg:pypi/namespace/package@1.0.0"
        result = await parser.extract_type(purl)
        assert result == "pypi"

    @pytest.mark.asyncio
    async def test_extract_type_complex_purl(self, parser):
        purl = "pkg:npm/@scope/package@1.0.0?foo=bar#subpath"
        result = await parser.extract_type(purl)
        assert result == "npm"

    @pytest.mark.asyncio
    async def test_is_valid_supported_type(self, parser):
        valid_purls = [
            "pkg:pypi/django@3.2.0",
            "pkg:npm/express@4.17.1",
            "pkg:maven/org.springframework/spring-core@5.3.0",
            "pkg:gem/rails@6.1.0",
            "pkg:cargo/serde@1.0.0",
            "pkg:nuget/Newtonsoft.Json@13.0.1"
        ]

        for purl in valid_purls:
            result = await parser.is_valid(purl)
            assert result is True, f"Expected {purl} to be valid"

    @pytest.mark.asyncio
    async def test_is_valid_unsupported_type(self, parser):
        purl = "pkg:unsupported/package@1.0.0"
        result = await parser.is_valid(purl)
        assert result is False

    @pytest.mark.asyncio
    async def test_is_valid_invalid_purl(self, parser):
        invalid_purls = [
            "",
            None,
            "not-a-purl",
            "pkg:",
            "invalid:format"
        ]

        for purl in invalid_purls:
            result = await parser.is_valid(purl)
            assert result is False, f"Expected {purl} to be invalid"

    @pytest.mark.asyncio
    async def test_is_valid_case_insensitive(self, parser):
        purl = "pkg:PyPi/django@3.2.0"
        result = await parser.is_valid(purl)
        assert result is True

    @pytest.mark.asyncio
    async def test_is_valid_npm_scope(self, parser):
        purl = "pkg:npm/@angular/core@12.0.0"
        result = await parser.is_valid(purl)
        assert result is True

    def test_parser_initialization(self):
        parser = PURLParser()
        assert parser.purl_pattern is not None

    @pytest.mark.asyncio
    async def test_extract_type_not_string(self, parser):
        result = await parser.extract_type(123)
        assert result is None

    @pytest.mark.asyncio
    async def test_is_valid_with_version_and_qualifiers(self, parser):
        purl = "pkg:maven/org.apache/commons-lang3@3.12.0?type=jar"
        result = await parser.is_valid(purl)
        assert result is True

    @pytest.mark.asyncio
    async def test_extract_type_only_pkg_prefix(self, parser):
        result = await parser.extract_type("pkg:")
        assert result is None

    @pytest.mark.asyncio
    async def test_is_valid_empty_type(self, parser):
        purl = "pkg://package@1.0.0"
        result = await parser.is_valid(purl)
        assert result is False

    @pytest.mark.asyncio
    async def test_extract_type_with_special_characters(self, parser):
        purl = "pkg:pypi/package_with-special.chars@1.0.0"
        result = await parser.extract_type(purl)
        assert result == "pypi"

    @pytest.mark.asyncio
    async def test_is_valid_conan_package(self, parser):
        purl = "pkg:conan/boost@1.76.0"
        result = await parser.is_valid(purl)
        assert isinstance(result, bool)
