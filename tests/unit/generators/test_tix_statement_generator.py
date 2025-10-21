from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.domain.vex_generation.generators.tix_statement_generator import (
    TIXStatementGenerator,
)


@pytest.mark.asyncio
class TestTIXStatementGenerator:

    @pytest.fixture
    def temp_dir(self):
        with TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def generator(self, temp_dir):
        return TIXStatementGenerator(temp_dir)

    @pytest.fixture
    def sample_vulnerability(self):
        return {
            "id": "CVE-2023-12345",
            "details": "Critical vulnerability description",
            "vuln_impact": 7.5,
            "attack_vector": "NETWORK",
            "cwes": [
                {"id": "CWE-79", "ExternalReference": "https://cwe.mitre.org/data/definitions/79.html", "@Abstraction": "Base", "Description": "XSS"},
                {"id": "CWE-89", "ExternalReference": "https://cwe.mitre.org/data/definitions/89.html", "@Abstraction": "Base", "Description": "SQL Injection"}
            ],
            "exploits": [
                {"id": "exp1", "type": "githubexploit", "href": "https://github.com/exploit1", "description": "payload1"},
                {"id": "exp2", "type": "other", "href": "https://exploit2.com", "description": "desc2", "sourceData": "data2"}
            ],
            "affected_artefacts": {"class1": ["method1", "method2"]}
        }

    async def test_generate_tix_statement(self, generator, sample_vulnerability):
        with patch("app.domain.vex_generation.generators.tix_statement_generator.create_tix_statement_template") as mock_template:
            mock_template.return_value = {
                "vulnerability": {
                    "@id": "",
                    "name": "",
                    "description": "",
                    "cvss": {"vuln_impact": "", "attack_vector": ""},
                    "cwes": []
                },
                "products": [{"identifiers": {"purl": ""}}],
                "reachable_code": [],
                "exploits": []
            }

            with patch.object(generator, "populate_reachable_code", new_callable=AsyncMock):
                with patch.object(generator, "populate_exploits", new_callable=AsyncMock):
                    result = await generator.generate_tix_statement(
                        vulnerability=sample_vulnerability,
                        purl="pkg:npm/example@1.0.0",
                        timestamp="2023-10-20T12:00:00Z",
                        import_names=["example"],
                        node_type="npm"
                    )

        assert result["vulnerability"]["name"] == "CVE-2023-12345"
        assert result["vulnerability"]["description"] == "Critical vulnerability description"
        assert result["vulnerability"]["cvss"]["vuln_impact"] == 7.5
        assert result["products"][0]["identifiers"]["purl"] == "pkg:npm/example@1.0.0"

    async def test_populate_vulnerability_info(self, generator, sample_vulnerability):
        tix_statement = {
            "vulnerability": {
                "@id": "",
                "name": "",
                "description": "",
                "cvss": {"vuln_impact": "", "attack_vector": ""},
                "cwes": []
            },
            "products": [{"identifiers": {"purl": ""}}]
        }

        await generator.populate_vulnerability_info(
            tix_statement,
            sample_vulnerability,
            "pkg:npm/example@1.0.0",
            "2023-10-20T12:00:00Z"
        )

        assert tix_statement["vulnerability"]["name"] == "CVE-2023-12345"
        assert tix_statement["vulnerability"]["description"] == "Critical vulnerability description"
        assert tix_statement["vulnerability"]["cvss"]["vuln_impact"] == 7.5
        assert tix_statement["vulnerability"]["cvss"]["attack_vector"] == "NETWORK"
        assert len(tix_statement["vulnerability"]["cwes"]) == 2

    async def test_populate_vulnerability_info_no_cwes(self, generator):
        tix_statement = {
            "vulnerability": {
                "@id": "",
                "name": "",
                "description": "",
                "cvss": {"vuln_impact": "", "attack_vector": ""},
                "cwes": []
            },
            "products": [{"identifiers": {"purl": ""}}]
        }
        vulnerability = {
            "id": "CVE-2023-12345",
            "details": "Test",
            "vuln_impact": 7.5,
            "attack_vector": "NETWORK"
        }

        await generator.populate_vulnerability_info(
            tix_statement,
            vulnerability,
            "pkg:npm/example@1.0.0",
            "2023-10-20T12:00:00Z"
        )

        assert len(tix_statement["vulnerability"]["cwes"]) == 0

    async def test_populate_reachable_code(self, generator, sample_vulnerability):
        tix_statement = {"reachable_code": []}

        with patch.object(generator, "get_files_path", return_value=AsyncMock(return_value=[])):
            await generator.populate_reachable_code(
                tix_statement,
                sample_vulnerability,
                ["example"],
                "npm"
            )

        assert isinstance(tix_statement["reachable_code"], list)

    async def test_build_reachable_code_entry(self, generator, sample_vulnerability, temp_dir):
        test_file = Path(temp_dir) / "test.js"
        test_file.write_text("const example = require('example');")

        mock_analyzer = MagicMock()
        mock_analyzer.get_used_artefacts = AsyncMock(return_value=["method1", "method2"])

        result = await generator.build_reachable_code_entry(
            str(test_file),
            sample_vulnerability,
            ["example"],
            mock_analyzer
        )

        assert "path_to_file" in result
        assert "used_artefacts" in result
        assert result["used_artefacts"] == ["method1", "method2"]

    async def test_populate_exploits(self, generator, sample_vulnerability):
        tix_statement = {"exploits": []}

        await generator.populate_exploits(tix_statement, sample_vulnerability)

        assert len(tix_statement["exploits"]) == 2

    async def test_populate_exploits_skip_unknown(self, generator):
        tix_statement = {"exploits": []}
        vulnerability = {
            "exploits": [
                {"id": "Unknown", "href": "Unknown"},
                {"id": "exp2", "type": "other", "href": "https://exploit2.com", "description": "Test", "sourceData": "data"}
            ]
        }

        await generator.populate_exploits(tix_statement, vulnerability)

        assert len(tix_statement["exploits"]) == 1

    async def test_get_files_path(self, generator, temp_dir):
        test_file = Path(temp_dir) / "test.py"
        test_file.write_text("import example")

        skip_dir = Path(temp_dir) / "node_modules"
        skip_dir.mkdir()
        skip_file = skip_dir / "skip.py"
        skip_file.write_text("import skip")

        with patch("app.domain.vex_generation.parsers.node_type_mapper.NodeTypeMapper.get_extension", return_value=".py"):
            result = await generator.get_files_path("pypi")

        assert len(result) == 1
        assert str(test_file) in result
        assert str(skip_file) not in result

    async def test_get_files_path_empty_directory(self, generator):
        with patch("app.domain.vex_generation.parsers.node_type_mapper.NodeTypeMapper.get_extension", return_value=".py"):
            result = await generator.get_files_path("pypi")

        assert isinstance(result, list)
