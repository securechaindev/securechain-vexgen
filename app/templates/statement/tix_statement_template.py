from copy import deepcopy
from functools import lru_cache


@lru_cache
def template() -> dict:
    return (
        {
            "vulnerability": {
                "@id": "",
                "name": "",
                "description": "",
                "cvss": {
                    "vuln_impact": 0.0,
                    "attack_vector": ""
                },
                "cwes": []
            },
            "products": [
                {
                    "identifiers": {
                        "purl": ""
                    }
                }
            ],
            "reachable_code": [],
            "exploits": [],
            "timestamp": "",
            "last_updated": ""
        }
    )


async def create_tix_statement_template() -> dict:
    return deepcopy(template())
