from typing import Any


class StatementHelpers:
    @staticmethod
    def set_timestamps(file: dict[str, Any], timestamp: str) -> None:
        file["timestamp"] = timestamp
        file["last_updated"] = timestamp

    @staticmethod
    def build_vulnerability_id(vuln_id: str) -> str:
        return f"https://osv.dev/vulnerability/{vuln_id}"

    @staticmethod
    def build_cwe_dict(cwe: dict[str, Any]) -> dict[str, Any]:
        return {
            "@id": cwe.get("ExternalReference", ""),
            "abstraction": cwe.get("@Abstraction", ""),
            "name": cwe.get("id", ""),
            "description": cwe.get("Description", "")
        }

    @staticmethod
    def build_exploit_dict(exploit: dict[str, Any]) -> dict[str, Any]:
        is_github_exploit = exploit.get("type") == "githubexploit"

        description = "" if is_github_exploit else exploit.get("description", "")
        payload = exploit.get("description", "") if is_github_exploit else exploit.get("sourceData", "")

        return {
            "name": exploit.get("id", "Unknown"),
            "@id": exploit.get("href", "Unknown"),
            "attack_vector": exploit.get("cvss", {}).get("vector", "NONE"),
            "description": description,
            "payload": payload
        }
