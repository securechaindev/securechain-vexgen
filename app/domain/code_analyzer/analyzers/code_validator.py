from regex import findall, search


class CodeValidator:
    @staticmethod
    async def is_relevant(artefact: str, artefacts: list[str], cve_description: str) -> bool:
        return (
            artefact in artefacts or
            artefact.lower() in cve_description.lower()
        )

    @staticmethod
    def is_valid_artefact_name(name: str) -> bool:
        if not name or len(name.strip()) < 2:
            return False

        name = name.strip()

        invalid_symbols = [
            '"', "'", '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
            '[', ']', '{', '}', '|', '\\', ':', ';', '<', '>', '?',
            '/', ',', '.', '~', '`', '-', '_', '=', '+'
        ]
        if name in invalid_symbols:
            return False

        if not search(r'[a-zA-Z0-9]', name):
            return False

        alphanumeric_count = len(findall(r'[a-zA-Z0-9]', name))
        if alphanumeric_count < len(name) * 0.5:
            return False

        return True
