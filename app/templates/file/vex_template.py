from copy import deepcopy
from functools import lru_cache


@lru_cache
def template() -> dict:
    return (
        {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://github.com/securechaindev/securechain-vexgen",
            "author": "",
            "role": "Generate Automated VEX with Secure Chain VEXGen",
            "timestamp": "",
            "last_updated": "",
            "version": 1,
            "tooling": "https://github.com/securechaindev/securechain-vexgen",
            "statements": []
        }
    )


def create_vex_template() -> dict:
    return deepcopy(template())
