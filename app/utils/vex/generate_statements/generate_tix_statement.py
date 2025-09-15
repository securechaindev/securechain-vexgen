from typing import Any

from app.templates import create_tix_statement_template
from app.utils.code_analyzer import get_used_artefacts, is_imported

from .generate_vex_properties import generate_vex_properties


async def generate_tix_statement(
    vulnerability: dict[str, Any],
    purl: str,
    timestamp: str,
    paths: list[str],
    import_names: list[str],
    node_type: str
) -> tuple[float, str, str, dict[str, Any]]:
    statement = await create_tix_statement_template()
    statement["vulnerability"]["@id"] = f"https://osv.dev/vulnerability/{vulnerability.get('id', '')}"
    statement["vulnerability"]["name"] = vulnerability.get("id", "")
    statement["vulnerability"]["description"] = vulnerability.get("details", "")
    statement["vulnerability"]["cvss"]["vuln_impact"] = vulnerability.get("vuln_impact", "")
    statement["vulnerability"]["cvss"]["attack_vector"] = vulnerability.get("attack_vector", "")
    statement["products"][0]["identifiers"]["purl"] = purl
    statement["timestamp"] = timestamp
    statement["last_updated"] = timestamp
    for cwe in vulnerability.get("cwes", []):
        _cwe = {}
        _cwe["@id"] = cwe.get("ExternalReference", "")
        _cwe["abstraction"] = cwe.get("@Abstraction", "")
        _cwe["name"] = cwe.get("id", "")
        _cwe["description"] = cwe.get("Description", "Don't have description.")
        statement["vulnerability"]["cwes"].append(_cwe)
    is_imported_any = False
    for path in paths:
        if await is_imported(path, import_names, node_type):
            is_imported_any = True
            reacheable_code = {}
            reacheable_code["path_to_file"] = path.replace("repositories/", "")
            affected_artefacts = {}
            affected_artefacts = vulnerability.get("affected_artefacts", {})
            reacheable_code["used_artefacts"] = await get_used_artefacts(path, import_names, vulnerability.get("details", ""), affected_artefacts, node_type)
            if reacheable_code["used_artefacts"]:
                statement["reachable_code"].append(reacheable_code)
    for exploit in vulnerability.get("exploits", []):
        _exploit = {}
        _exploit["@id"] = exploit.get("href", "Unknown")
        _exploit["attack_vector"] = exploit.get("cvss", {}).get("vector", "NONE")
        _exploit["description"] = "" if exploit.get("type") == "githubexploit" else exploit.get("description", "")
        _exploit["payload"] = ""
        if exploit.get("type") == "githubexploit":
            _exploit["payload"] = exploit.get("description", "")
        else:
            if "sourceData" in exploit:
                _exploit["payload"] = exploit.get("sourceData", "")
        statement["exploits"].append(_exploit)
    priority, status, justification, impact_statement = await generate_vex_properties(vulnerability, statement, is_imported_any)
    return priority, status, justification, impact_statement, statement
