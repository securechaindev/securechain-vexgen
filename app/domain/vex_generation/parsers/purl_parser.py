from regex import Pattern, compile

from .node_type_mapper import NodeTypeMapper


class PURLParser:
    def __init__(self) -> None:
        self.purl_pattern: Pattern= compile(r'^pkg:([^/]+)/.*$')

    def extract_type(self, purl: str) -> str | None:
        if not purl or not isinstance(purl, str):
            return None

        if ':' not in purl:
            return None

        match = self.purl_pattern.match(purl)
        return match.group(1) if match else None

    def is_valid(self, purl: str) -> bool:
        purl_type = self.extract_type(purl)
        if purl_type is None:
            return False
        return purl_type.lower() in NodeTypeMapper.get_supported_purl_types()
