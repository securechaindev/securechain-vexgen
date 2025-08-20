from copy import deepcopy
from functools import lru_cache


@lru_cache
def template() -> dict:
    return (
        {
            "vulnerability": {
                "@id": "",
                "name": "",
                "description": ""
            },
            "products": [
                {
                    "identifiers": {
                        "purl": ""
                    }
                }
            ],
            "timestamp": "",
            "last_updated": "",
            "supplier": "",
            "status": "VEXGen has not been able to check if you are affected by the vulnerability. Check the TIX document to find intelligence information about the vulnerability.",
            "justification": ""
        }
    )


async def create_vex_statement_template() -> dict:
    return deepcopy(template())
