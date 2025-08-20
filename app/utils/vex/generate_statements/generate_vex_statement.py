from typing import Any

from app.templates import create_vex_statement_template


async def generate_vex_statement(
    vulnerability: dict[str, Any],
    purl: str,
    node_type: str,
    timestamp: str,
    status: str,
    justification: str,
    impact_statement: str,
    priority: float
) -> dict[str, Any]:
    statement = await create_vex_statement_template()
    statement["vulnerability"]["@id"] = f"https://osv.dev/vulnerability/{vulnerability["id"]}"
    statement["vulnerability"]["name"] = vulnerability["id"]
    statement["vulnerability"]["description"] = vulnerability["details"]
    statement["products"][0]["identifiers"]["purl"] = purl
    statement["supplier"] = node_type
    statement["timestamp"] = timestamp
    statement["last_updated"] = timestamp
    statement["status"] = status
    statement["justification"] = justification
    statement["impact_statement"] = impact_statement
    statement["priority"] = priority
    return statement
