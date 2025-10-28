from typing import Any

from app.settings import settings
from app.templates import create_vex_statement_template

from .statement_helpers import StatementHelpers


class VEXStatementGenerator:
    def __init__(self):
        self.vulnerability_impact_weight = settings.VEX_VULNERABILITY_IMPACT_WEIGHT
        self.reachable_code_priority_bonus = settings.VEX_REACHABLE_CODE_PRIORITY_BONUS
        self.exploits_priority_bonus = settings.VEX_EXPLOITS_PRIORITY_BONUS
        self.cwes_priority_bonus = settings.VEX_CWES_PRIORITY_BONUS

    async def generate_vex_statement(
        self,
        vulnerability: dict[str, Any],
        purl: str,
        node_type: str,
        timestamp: str,
        tix_statement: dict[str, Any],
        is_dependency_imported: bool,
    ) -> dict[str, Any]:
        vex_statement = create_vex_statement_template()
        vex_statement["vulnerability"]["@id"] = StatementHelpers.build_vulnerability_id(vulnerability["id"])
        vex_statement["vulnerability"]["name"] = vulnerability["id"]
        vex_statement["vulnerability"]["description"] = vulnerability["details"]
        vex_statement["products"][0]["identifiers"]["purl"] = purl
        vex_statement["supplier"] = node_type
        StatementHelpers.set_timestamps(vex_statement, timestamp)
        await self.add_vex_properties(
            vex_statement,
            tix_statement,
            vulnerability,
            is_dependency_imported
        )
        await self.add_vex_priority(vex_statement, vulnerability["vuln_impact"])
        return vex_statement

    async def add_vex_properties(
        self,
        vex_statement: dict[str, Any],
        tix_statement: dict[str, Any],
        vulnerability: dict[str, Any],
        is_dependency_imported: bool,
    ) -> None:
        status = "under_investigation"
        justification = "It is needed to analyze the code reachability to determine the status of the vulnerability."
        impact_statement = "The vulnerability does not have affected artefacts. The status cannot be inferred."
        if "affected_artefacts" in vulnerability:
            if not is_dependency_imported:
                status = "not_affected"
                justification = "component_not_present"
                impact_statement = "The dependency is not imported in the code."
            elif is_dependency_imported and not tix_statement.get("reachable_code", []):
                status = "not_affected"
                justification = "vulnerable_code_not_present"
                impact_statement = "There is no affected artefact present in the code."
            else:
                impact_statement = "The code contains vulnerable artefacts that you should check to see if you are actually affected by the vulnerability."
        vex_statement["status"] = status
        vex_statement["justification"] = justification
        vex_statement["impact_statement"] = impact_statement

    async def add_vex_priority(
        self,
        vex_statement: dict[str, Any],
        vulnerability_impact: float
    ) -> None:
        priority = vulnerability_impact * self.vulnerability_impact_weight

        if vex_statement.get("reachable_code", []):
            priority += self.reachable_code_priority_bonus
        if vex_statement.get("exploits", []):
            priority += self.exploits_priority_bonus
        if vex_statement.get("vulnerability", {}).get("cwes", []):
            priority += self.cwes_priority_bonus

        vex_statement["priority"] = round(priority, 2)
