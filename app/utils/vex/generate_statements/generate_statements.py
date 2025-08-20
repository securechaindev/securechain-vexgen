from typing import Any

from app.services import (
    read_package_by_name,
    read_vulnerability_by_id,
    read_vulnerability_ids_by_version_and_package,
)
from app.utils.others import get_node_type

from .generate_tix_statement import generate_tix_statement
from .generate_vex_statement import generate_vex_statement


async def generate_statements(
    components: list[dict[str, Any]],
    paths: list[str],
    timestamp: str,
    vex: dict[str, Any],
    tix: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    for component in components:
        if "name" in component:
            if "purl" in component and "version" in component:
                node_type = await get_node_type(component["purl"])
                package_name, import_name = await read_package_by_name(node_type, component["name"].lower())
                vulnerabilities_ids = await read_vulnerability_ids_by_version_and_package(
                    node_type, package_name, component["version"]
                )
                for vulnerability_id in vulnerabilities_ids:
                    vulnerability = await read_vulnerability_by_id(vulnerability_id)
                    priority, status, justification, impact_statement, tix_statement = await generate_tix_statement(
                        vulnerability,
                        component["purl"],
                        timestamp,
                        paths,
                        import_name,
                        package_name,
                        node_type
                    )
                    tix["statements"].append(tix_statement)
                    vex["statements"].append(
                        await generate_vex_statement(
                            vulnerability,
                            component["purl"],
                            node_type,
                            timestamp,
                            status,
                            justification,
                            impact_statement,
                            priority
                        )
                    )
    vex["statements"] = sorted(vex["statements"], key=lambda d: d['priority'], reverse=True)
    return vex, tix
