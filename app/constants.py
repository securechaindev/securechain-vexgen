from enum import Enum


class RateLimit(str, Enum):
    DEFAULT = "25/minute"
    GENERATE_VEX = "10/minute"
    GENERATE_TIX = "10/minute"
    HEALTH_CHECK = "100/minute"
    DOWNLOAD = "5/minute"


class GitRules:
    ALLOWED_GIT_HOSTS = frozenset([
        "github.com",
        "gitlab.com",
        "bitbucket.org",
    ])
    DANGEROUS_URL_PATTERNS = frozenset([
        "file://",
        "git://",
        "ssh://",
        "ext::",
        "fd::",
        "pserver:",
    ])
    MAX_REPO_SIZE_MB = 500
    GIT_TIMEOUT_SECONDS = 300


class FileRules:
    ALLOWED_SBOM_EXTENSIONS = frozenset([
        ".json",
        ".xml",
        ".spdx",
        ".cdx",
    ])
    DANGEROUS_PATH_COMPONENTS = frozenset([
        "..",
        "~",
        "/etc",
        "/proc",
        "/sys",
        "/dev",
        "\\",
    ])
    MAX_FILE_SIZE_MB = 10
