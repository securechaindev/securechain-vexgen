from typing import Any


async def generate_vex_properties(vulnerability: dict[str, Any], statement: dict[str, Any], is_imported_any: bool) -> tuple[str, str, str, float]:
    status = ""
    justification = ""
    impact_statement = ""
    if "affected_artefacts" in vulnerability:
        if not is_imported_any:
            status = "not_affected"
            justification = "component_not_present"
        elif is_imported_any and not statement.get("reachable_code", []):
            status = "not_affected"
            justification = "vulnerable_code_not_present"
        else:
            impact_statement = "The code contains vulnerable artefacts that you should check to see if you are actually affected by the vulnerability."
    priority = vulnerability["vuln_impact"]*0.7
    if statement.get("reachable_code", []):
        priority += 1
    if statement.get("exploits", []):
        priority += 1
    if statement.get("vulnerability", {}).get("cwes", []):
        priority += 1
    return status, justification, impact_statement, priority
