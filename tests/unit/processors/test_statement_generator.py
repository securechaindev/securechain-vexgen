
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.domain.vex_generation.processors.statement_generator import StatementsGenerator
from app.exceptions import ComponentNotSupportedException


class TestStatementsGenerator:

    @pytest.fixture
    def mock_package_service(self):
        service = AsyncMock()
        service.read_package_by_name.return_value = ("package-name", ["import1", "import2"])
        return service

    @pytest.fixture
    def mock_version_service(self):
        service = AsyncMock()
        service.read_vulnerability_ids_by_version_and_package.return_value = ["CVE-2023-1234"]
        return service

    @pytest.fixture
    def mock_vulnerability_service(self):
        service = AsyncMock()
        service.read_vulnerability_by_id.return_value = {
            "id": "CVE-2023-1234",
            "description": "Test vulnerability",
            "severity": "HIGH"
        }
        return service

    @pytest.fixture
    def generator(self, mock_package_service, mock_version_service, mock_vulnerability_service):
        with patch('app.domain.vex_generation.processors.statement_generator.DatabaseManager'):
            return StatementsGenerator(
                directory="/tmp/test",
                package_service=mock_package_service,
                version_service=mock_version_service,
                vulnerability_service=mock_vulnerability_service
            )

    def test_initialization(self, generator):
        assert generator.directory == "/tmp/test"
        assert generator.component_name_key == "name"
        assert generator.component_purl_key == "purl"
        assert generator.component_version_key == "version"
        assert generator.package_service is not None
        assert generator.version_service is not None
        assert generator.vulnerability_service is not None

    @pytest.mark.asyncio
    async def test_is_valid_component_complete(self, generator):
        component = {
            "name": "express",
            "version": "4.18.0",
            "purl": "pkg:npm/express@4.18.0"
        }

        with patch.object(generator.purl_parser, 'is_valid', return_value=True):
            result = await generator.is_valid_component(component)
            assert result is True

    @pytest.mark.asyncio
    async def test_is_valid_component_missing_name(self, generator):
        component = {
            "version": "4.18.0",
            "purl": "pkg:npm/express@4.18.0"
        }

        result = await generator.is_valid_component(component)
        assert result is False

    @pytest.mark.asyncio
    async def test_is_valid_component_invalid_name_type(self, generator):
        component = {
            "name": 123,
            "version": "4.18.0",
            "purl": "pkg:npm/express@4.18.0"
        }

        result = await generator.is_valid_component(component)
        assert result is False

    @pytest.mark.asyncio
    async def test_is_valid_component_missing_purl(self, generator):
        component = {
            "name": "express",
            "version": "4.18.0"
        }

        result = await generator.is_valid_component(component)
        assert result is False

    @pytest.mark.asyncio
    async def test_is_valid_component_missing_version(self, generator):
        component = {
            "name": "express",
            "purl": "pkg:npm/express@4.18.0"
        }

        result = await generator.is_valid_component(component)
        assert result is False

    @pytest.mark.asyncio
    async def test_is_valid_component_invalid_purl(self, generator):
        component = {
            "name": "express",
            "version": "4.18.0",
            "purl": "invalid-purl"
        }

        with patch.object(generator.purl_parser, 'is_valid', return_value=False):
            result = await generator.is_valid_component(component)
            assert result is False

    @pytest.mark.asyncio
    async def test_is_valid_component_empty_name(self, generator):
        component = {
            "name": "",
            "version": "4.18.0",
            "purl": "pkg:npm/express@4.18.0"
        }

        with patch.object(generator.purl_parser, 'is_valid', return_value=True):
            result = await generator.is_valid_component(component)
            assert result is True

    def test_map_node_type(self, generator):
        with patch('app.domain.vex_generation.processors.statement_generator.NodeTypeMapper.purl_type_to_node_type') as mock_map:
            mock_map.return_value = "Pypi"

            result = generator.map_node_type("pypi")

            assert result == "Pypi"
            mock_map.assert_called_once_with("pypi")

    def test_map_node_type_unsupported(self, generator):
        with patch('app.domain.vex_generation.processors.statement_generator.NodeTypeMapper.purl_type_to_node_type') as mock_map:
            mock_map.side_effect = ComponentNotSupportedException()

            with pytest.raises(ComponentNotSupportedException):
                generator.map_node_type("unknown")

    @pytest.mark.asyncio
    async def test_process_vulnerability(self, generator):
        vex = {"statements": []}
        tix = {"statements": []}

        vulnerability = {
            "id": "CVE-2023-1234",
            "description": "Test vulnerability"
        }

        tix_statement = {"vulnerability": "CVE-2023-1234", "analysis": "not_affected"}
        vex_statement = {"vulnerability": "CVE-2023-1234", "status": "not_affected"}

        generator.vulnerability_service.read_vulnerability_by_id.return_value = vulnerability
        generator.tix_statement_generator.generate_tix_statement = AsyncMock(return_value=tix_statement)
        generator.vex_statement_generator.generate_vex_statement = AsyncMock(return_value=vex_statement)

        await generator.process_vulnerability(
            "CVE-2023-1234",
            "pkg:npm/express@4.18.0",
            "2024-01-01T00:00:00Z",
            ["express"],
            "Npm",
            vex,
            tix
        )

        assert len(vex["statements"]) == 1
        assert len(tix["statements"]) == 1
        assert vex["statements"][0] == vex_statement
        assert tix["statements"][0] == tix_statement

    @pytest.mark.asyncio
    async def test_process_component_complete_flow(self, generator):
        component = {
            "name": "express",
            "version": "4.18.0",
            "purl": "pkg:npm/express@4.18.0"
        }
        vex = {"statements": []}
        tix = {"statements": []}

        generator.purl_parser.extract_type = AsyncMock(return_value="npm")
        generator.package_service.read_package_by_name.return_value = ("express", ["express"])
        generator.version_service.read_vulnerability_ids_by_version_and_package.return_value = ["CVE-2023-1234"]

        vulnerability = {"id": "CVE-2023-1234"}
        generator.vulnerability_service.read_vulnerability_by_id.return_value = vulnerability

        tix_statement = {"vulnerability": "CVE-2023-1234"}
        vex_statement = {"vulnerability": "CVE-2023-1234", "priority": 5}

        generator.tix_statement_generator.generate_tix_statement = AsyncMock(return_value=tix_statement)
        generator.vex_statement_generator.generate_vex_statement = AsyncMock(return_value=vex_statement)

        await generator.process_component(component, "2024-01-01T00:00:00Z", vex, tix)

        assert len(vex["statements"]) == 1
        assert len(tix["statements"]) == 1

    @pytest.mark.asyncio
    async def test_process_component_no_purl_type(self, generator):
        component = {
            "name": "express",
            "version": "4.18.0",
            "purl": "pkg:npm/express@4.18.0"
        }
        vex = {"statements": []}
        tix = {"statements": []}

        generator.purl_parser.extract_type = AsyncMock(return_value=None)

        await generator.process_component(component, "2024-01-01T00:00:00Z", vex, tix)

        assert len(vex["statements"]) == 0
        assert len(tix["statements"]) == 0

    @pytest.mark.asyncio
    async def test_process_component_unsupported_type(self, generator):
        component = {
            "name": "express",
            "version": "4.18.0",
            "purl": "pkg:unknown/express@4.18.0"
        }
        vex = {"statements": []}
        tix = {"statements": []}

        generator.purl_parser.extract_type = AsyncMock(return_value="unknown")

        with patch.object(generator, 'map_node_type', side_effect=ComponentNotSupportedException()):
            await generator.process_component(component, "2024-01-01T00:00:00Z", vex, tix)

        assert len(vex["statements"]) == 0
        assert len(tix["statements"]) == 0

    @pytest.mark.asyncio
    async def test_process_component_no_vulnerabilities(self, generator):
        component = {
            "name": "express",
            "version": "4.18.0",
            "purl": "pkg:npm/express@4.18.0"
        }
        vex = {"statements": []}
        tix = {"statements": []}

        generator.purl_parser.extract_type = AsyncMock(return_value="npm")
        generator.package_service.read_package_by_name.return_value = ("express", ["express"])
        generator.version_service.read_vulnerability_ids_by_version_and_package.return_value = []

        await generator.process_component(component, "2024-01-01T00:00:00Z", vex, tix)

        assert len(vex["statements"]) == 0
        assert len(tix["statements"]) == 0

    @pytest.mark.asyncio
    async def test_process_component_multiple_vulnerabilities(self, generator):
        component = {
            "name": "express",
            "version": "4.18.0",
            "purl": "pkg:npm/express@4.18.0"
        }
        vex = {"statements": []}
        tix = {"statements": []}

        generator.purl_parser.extract_type = AsyncMock(return_value="npm")
        generator.package_service.read_package_by_name.return_value = ("express", ["express"])
        generator.version_service.read_vulnerability_ids_by_version_and_package.return_value = [
            "CVE-2023-1234",
            "CVE-2023-5678"
        ]

        generator.vulnerability_service.read_vulnerability_by_id.side_effect = [
            {"id": "CVE-2023-1234"},
            {"id": "CVE-2023-5678"}
        ]

        generator.tix_statement_generator.generate_tix_statement = AsyncMock(
            side_effect=[
                {"vulnerability": "CVE-2023-1234"},
                {"vulnerability": "CVE-2023-5678"}
            ]
        )
        generator.vex_statement_generator.generate_vex_statement = AsyncMock(
            side_effect=[
                {"vulnerability": "CVE-2023-1234"},
                {"vulnerability": "CVE-2023-5678"}
            ]
        )

        await generator.process_component(component, "2024-01-01T00:00:00Z", vex, tix)

        assert len(vex["statements"]) == 2
        assert len(tix["statements"]) == 2

    @pytest.mark.asyncio
    async def test_generate_statements_sorts_by_priority(self, generator):
        components = [
            {
                "name": "pkg1",
                "version": "1.0.0",
                "purl": "pkg:npm/pkg1@1.0.0"
            },
            {
                "name": "pkg2",
                "version": "2.0.0",
                "purl": "pkg:npm/pkg2@2.0.0"
            }
        ]
        vex = {"statements": []}
        tix = {"statements": []}

        generator.purl_parser.is_valid = AsyncMock(return_value=True)
        generator.purl_parser.extract_type = AsyncMock(return_value="npm")

        generator.package_service.read_package_by_name.return_value = ("pkg", ["pkg"])
        generator.version_service.read_vulnerability_ids_by_version_and_package.return_value = ["CVE-1"]
        generator.vulnerability_service.read_vulnerability_by_id.return_value = {"id": "CVE-1"}

        call_count = [0]

        async def mock_tix_gen(*args, **kwargs):
            return {"vulnerability": f"CVE-{call_count[0]}"}

        async def mock_vex_gen(*args, **kwargs):
            priority = 10 if call_count[0] == 0 else 5
            call_count[0] += 1
            return {"vulnerability": f"CVE-{call_count[0]-1}", "priority": priority}

        generator.tix_statement_generator.generate_tix_statement = mock_tix_gen
        generator.vex_statement_generator.generate_vex_statement = mock_vex_gen

        result_vex, _result_tix = await generator.generate_statements(
            components,
            "2024-01-01T00:00:00Z",
            vex,
            tix
        )

        assert len(result_vex["statements"]) == 2
        assert result_vex["statements"][0]["priority"] == 10
        assert result_vex["statements"][1]["priority"] == 5

    @pytest.mark.asyncio
    async def test_generate_statements_skips_invalid_components(self, generator):
        components = [
            {
                "name": "valid-pkg",
                "version": "1.0.0",
                "purl": "pkg:npm/valid-pkg@1.0.0"
            },
            {
                "name": 123,
                "version": "1.0.0",
                "purl": "pkg:npm/invalid@1.0.0"
            },
            {
                "version": "1.0.0",
                "purl": "pkg:npm/missing@1.0.0"
            }
        ]
        vex = {"statements": []}
        tix = {"statements": []}

        generator.purl_parser.is_valid = AsyncMock(return_value=True)
        generator.purl_parser.extract_type = AsyncMock(return_value="npm")
        generator.package_service.read_package_by_name.return_value = ("pkg", ["pkg"])
        generator.version_service.read_vulnerability_ids_by_version_and_package.return_value = ["CVE-1"]
        generator.vulnerability_service.read_vulnerability_by_id.return_value = {"id": "CVE-1"}

        generator.tix_statement_generator.generate_tix_statement = AsyncMock(
            return_value={"vulnerability": "CVE-1"}
        )
        generator.vex_statement_generator.generate_vex_statement = AsyncMock(
            return_value={"vulnerability": "CVE-1", "priority": 5}
        )

        await generator.generate_statements(components, "2024-01-01T00:00:00Z", vex, tix)

        assert len(vex["statements"]) == 1
        assert len(tix["statements"]) == 1

    @pytest.mark.asyncio
    async def test_generate_statements_empty_components(self, generator):
        vex = {"statements": []}
        tix = {"statements": []}

        result_vex, result_tix = await generator.generate_statements(
            [],
            "2024-01-01T00:00:00Z",
            vex,
            tix
        )

        assert len(result_vex["statements"]) == 0
        assert len(result_tix["statements"]) == 0

    @pytest.mark.asyncio
    async def test_generate_statements_preserves_existing_statements(self, generator):
        components = [
            {
                "name": "pkg",
                "version": "1.0.0",
                "purl": "pkg:npm/pkg@1.0.0"
            }
        ]
        vex = {"statements": [{"existing": "vex", "priority": 1}]}
        tix = {"statements": [{"existing": "tix"}]}

        generator.purl_parser.is_valid = AsyncMock(return_value=True)
        generator.purl_parser.extract_type = AsyncMock(return_value="npm")
        generator.package_service.read_package_by_name.return_value = ("pkg", ["pkg"])
        generator.version_service.read_vulnerability_ids_by_version_and_package.return_value = ["CVE-1"]
        generator.vulnerability_service.read_vulnerability_by_id.return_value = {"id": "CVE-1"}

        generator.tix_statement_generator.generate_tix_statement = AsyncMock(
            return_value={"vulnerability": "CVE-1"}
        )
        generator.vex_statement_generator.generate_vex_statement = AsyncMock(
            return_value={"vulnerability": "CVE-1", "priority": 5}
        )

        result_vex, result_tix = await generator.generate_statements(
            components,
            "2024-01-01T00:00:00Z",
            vex,
            tix
        )

        assert len(result_vex["statements"]) == 2
        assert len(result_tix["statements"]) == 2
        assert {"existing": "vex", "priority": 1} in result_vex["statements"]
        assert {"existing": "tix"} in result_tix["statements"]

    @pytest.mark.asyncio
    async def test_is_valid_component_name_none(self, generator):
        component = {
            "name": None,
            "version": "1.0.0",
            "purl": "pkg:npm/test@1.0.0"
        }

        result = await generator.is_valid_component(component)
        assert result is False

    @pytest.mark.asyncio
    async def test_initialization_with_default_services(self):
        with patch('app.domain.vex_generation.processors.statement_generator.DatabaseManager') as mock_db:
            mock_db.return_value = MagicMock()

            with patch('app.domain.vex_generation.processors.statement_generator.PackageService') as mock_pkg:
                with patch('app.domain.vex_generation.processors.statement_generator.VersionService') as mock_ver:
                    with patch('app.domain.vex_generation.processors.statement_generator.VulnerabilityService') as mock_vuln:
                        _generator = StatementsGenerator(directory="/tmp/test")

                        mock_pkg.assert_called_once()
                        mock_ver.assert_called_once()
                        mock_vuln.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_component_case_insensitive_package_name(self, generator):
        component = {
            "name": "Express",
            "version": "4.18.0",
            "purl": "pkg:npm/Express@4.18.0"
        }
        vex = {"statements": []}
        tix = {"statements": []}

        generator.purl_parser.extract_type = AsyncMock(return_value="npm")
        generator.package_service.read_package_by_name.return_value = ("express", ["express"])
        generator.version_service.read_vulnerability_ids_by_version_and_package.return_value = []

        await generator.process_component(component, "2024-01-01T00:00:00Z", vex, tix)

        generator.package_service.read_package_by_name.assert_called_once()
        call_args = generator.package_service.read_package_by_name.call_args[0]
        assert call_args[1] == "express"
