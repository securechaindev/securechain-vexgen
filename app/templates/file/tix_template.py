from copy import deepcopy
from functools import lru_cache


@lru_cache
def template() -> dict:
    return (
        {
            "@context": "https://github.com/securechaindev/securechain-vexgen/wiki/Thread-Intelligence-eXchange-(TIX)-Spec-v0.1.0",
            "@id": "https://github.com/securechaindev/securechain-vexgen",
            "author": "",
            "role": "Generate Automated TIX with Secure Chain VEXGen",
            "timestamp": "",
            "last_updated": "",
            "version": 1,
            "tooling": "https://github.com/securechaindev/securechain-vexgen",
            "statements": []
        }
    )


def create_tix_template() -> dict:
    return deepcopy(template())
