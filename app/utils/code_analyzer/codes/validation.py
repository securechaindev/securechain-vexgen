from regex import findall, search


def is_valid_artefact_name(name: str) -> bool:
    if not name or len(name.strip()) < 2:
        return False
    name = name.strip()
    if name in ['"', "'", '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
                '[', ']', '{', '}', '|', '\\', ':', ';', '<', '>', '?',
                '/', ',', '.', '~', '`', '-', '_', '=', '+']:
        return False
    if not search(r'[a-zA-Z0-9]', name):
        return False
    alphanumeric_count = len(findall(r'[a-zA-Z0-9]', name))
    if alphanumeric_count < len(name) * 0.5:
        return False
    return True
