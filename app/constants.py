from enum import Enum


class RateLimit(str, Enum):
    DEFAULT = "25/minute"
    GENERATE_VEX = "10/minute"
    GENERATE_TIX = "10/minute"
    HEALTH_CHECK = "100/minute"
    DOWNLOAD = "5/minute"


class GitConfig:
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


class FileConfig:
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


class DatabaseConfig:
    VEXS_COLLECTION = "vexs"
    TIXS_COLLECTION = "tixs"
    USERS_COLLECTION = "users"
    MIN_POOL_SIZE = 10
    MAX_POOL_SIZE = 100
    MAX_IDLE_TIME_MS = 60000
    DEFAULT_QUERY_TIMEOUT_MS = 5000
    LONG_QUERY_TIMEOUT_MS = 30000
