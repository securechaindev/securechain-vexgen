from unittest.mock import patch

import pytest

from app.domain.vex_generation.generators.vex_statement_generator import (
    VEXStatementGenerator,
)


@pytest.mark.asyncio
class TestVEXStatementGenerator:

    @pytest.fixture
    def generator(self):
        return VEXStatementGenerator()

    @pytest.fixture
    def sample_vulnerability(self):
        return {
            "id": "CVE-2023-12345",
            "details": "Critical vulnerability description",
            "vuln_impact": 7.5,
            "affected_artefacts": ["artifact1", "artifact2"]
        }

    @pytest.fixture
    def sample_tix_statement(self):
        return {
            "reachable_code": []
        }

    async def test_generate_vex_statement(self, generator, sample_vulnerability, sample_tix_statement):
        with patch("app.domain.vex_generation.generators.vex_statement_generator.create_vex_statement_template") as mock_template:
            mock_template.return_value = {
                "vulnerability": {"@id": "", "name": "", "description": ""},
                "products": [{"identifiers": {"purl": ""}}],
                "supplier": "",
                "status": "",
                "justification": "",
                "impact_statement": "",
                "priority": 0
            }

            result = await generator.generate_vex_statement(
                vulnerability=sample_vulnerability,
                purl="pkg:npm/example@1.0.0",
                node_type="npm",
                timestamp="2023-10-20T12:00:00Z",
                tix_statement=sample_tix_statement
            )

        assert result["vulnerability"]["name"] == "CVE-2023-12345"
        assert result["vulnerability"]["description"] == "Critical vulnerability description"
        assert result["products"][0]["identifiers"]["purl"] == "pkg:npm/example@1.0.0"
        assert result["supplier"] == "npm"
        assert "priority" in result

    async def test_add_vex_properties_not_affected_component_not_present(self, generator, sample_vulnerability, sample_tix_statement):
        vex_statement = {
            "status": "",
            "justification": "",
            "impact_statement": ""
        }

        await generator.add_vex_properties(vex_statement, sample_tix_statement, sample_vulnerability)

        assert vex_statement["status"] == "not_affected"
        assert vex_statement["justification"] == "component_not_present"

    async def test_add_vex_properties_not_affected_vulnerable_code_not_present(self, generator, sample_vulnerability):
        vex_statement = {
            "status": "",
            "justification": "",
            "impact_statement": ""
        }
        tix_statement = {
            "reachable_code": ["some_code"]
        }

        await generator.add_vex_properties(vex_statement, tix_statement, sample_vulnerability)

        assert vex_statement["status"] == "not_affected"
        assert vex_statement["justification"] == "vulnerable_code_not_present"

    async def test_add_vex_properties_under_investigation_no_affected_artefacts(self, generator, sample_tix_statement):
        vex_statement = {
            "status": "",
            "justification": "",
            "impact_statement": ""
        }
        vulnerability = {
            "id": "CVE-2023-12345",
            "details": "Test",
            "vuln_impact": 7.5
        }

        await generator.add_vex_properties(vex_statement, sample_tix_statement, vulnerability)

        assert vex_statement["status"] == "under_investigation"
        assert vex_statement["justification"] == ""
        assert "doesn't have affected artefacts" in vex_statement["impact_statement"]

    async def test_add_vex_priority_base_impact(self, generator):
        vex_statement = {}

        await generator.add_vex_priority(vex_statement, 7.5)

        assert vex_statement["priority"] == 7.5 * generator.vulnerability_impact_weight

    async def test_add_vex_priority_with_reachable_code(self, generator):
        vex_statement = {
            "reachable_code": ["code1", "code2"]
        }

        await generator.add_vex_priority(vex_statement, 7.5)

        expected = (7.5 * generator.vulnerability_impact_weight) + generator.reachable_code_priority_bonus
        assert vex_statement["priority"] == expected

    async def test_add_vex_priority_with_exploits(self, generator):
        vex_statement = {
            "exploits": ["exploit1"]
        }

        await generator.add_vex_priority(vex_statement, 7.5)

        expected = (7.5 * generator.vulnerability_impact_weight) + generator.exploits_priority_bonus
        assert vex_statement["priority"] == expected

    async def test_add_vex_priority_with_cwes(self, generator):
        vex_statement = {
            "vulnerability": {
                "cwes": ["CWE-79", "CWE-89"]
            }
        }

        await generator.add_vex_priority(vex_statement, 7.5)

        expected = (7.5 * generator.vulnerability_impact_weight) + generator.cwes_priority_bonus
        assert vex_statement["priority"] == expected

    async def test_add_vex_priority_all_bonuses(self, generator):
        vex_statement = {
            "reachable_code": ["code1"],
            "exploits": ["exploit1"],
            "vulnerability": {
                "cwes": ["CWE-79"]
            }
        }

        await generator.add_vex_priority(vex_statement, 7.5)

        expected = (7.5 * generator.vulnerability_impact_weight) + \
                   generator.reachable_code_priority_bonus + \
                   generator.exploits_priority_bonus + \
                   generator.cwes_priority_bonus
        assert vex_statement["priority"] == expected
