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

class ResponseCode:
    # Success codes
    SUCCESS_VEXS_RETRIEVED = "success_vexs_retrieved"
    SUCCESS_VEX_RETRIEVED = "success_vex_retrieved"
    SUCCESS_TIXS_RETRIEVED = "success_tixs_retrieved"
    SUCCESS_TIX_RETRIEVED = "success_tix_retrieved"
    SUCCESS_VEX_GENERATED = "success_vex_generated"
    SUCCESS_TIX_GENERATED = "success_tix_generated"
    SUCCESS_HEALTH_CHECK = "success_health_check"

    # Error codes - General
    VALIDATION_ERROR = "validation_error"
    HTTP_ERROR = "http_error"
    INTERNAL_ERROR = "internal_error"
    NOT_FOUND = "not_found"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"

    # Error codes - VEX/TIX specific
    ERROR_VEX_NOT_FOUND = "error_vex_not_found"
    ERROR_TIX_NOT_FOUND = "error_tix_not_found"

    # Error codes - SBOM
    INVALID_SBOM = "invalid_sbom"
    SBOM_NOT_FOUND = "sbom_not_found"

    # Error codes - Repository
    INVALID_REPOSITORY = "invalid_repository"
    CLONE_REPO_EXCEPTION = "clone_repo_error"
    COMPONENT_NOT_SUPPORTED = "component_not_supported"
    REPOSITORY_NOT_FOUND = "repository_not_found"

    # Error codes - Authentication
    INVALID_TOKEN = "invalid_token"
    TOKEN_EXPIRED = "token_expired"
    NOT_AUTHENTICATED = "not_authenticated"

class ResponseMessage:
    # Success messages
    SUCCESS_VEXS_RETRIEVED = "VEX documents retrieved successfully"
    SUCCESS_VEX_RETRIEVED = "VEX document retrieved successfully"
    SUCCESS_TIXS_RETRIEVED = "TIX documents retrieved successfully"
    SUCCESS_TIX_RETRIEVED = "TIX document retrieved successfully"
    SUCCESS_VEX_GENERATED = "VEX generated successfully"
    SUCCESS_TIX_GENERATED = "TIX generated successfully"
    SUCCESS_HEALTH_CHECK = "API is healthy"

    # Error messages - General
    VALIDATION_ERROR = "Validation error"
    HTTP_ERROR = "HTTP error"
    INTERNAL_ERROR = "Internal server error"
    NOT_FOUND = "Resource not found"
    UNAUTHORIZED = "Unauthorized access"
    FORBIDDEN = "Forbidden access"

    # Error messages - VEX/TIX specific
    ERROR_VEX_NOT_FOUND = "VEX document not found"
    ERROR_TIX_NOT_FOUND = "TIX document not found"

    # Error messages - SBOM
    INVALID_SBOM = "Invalid SBOM format"
    SBOM_NOT_FOUND = "SBOM not found"

    # Error messages - Repository
    INVALID_REPOSITORY = "Invalid repository"
    CLONE_REPO_EXCEPTION = "Failed to clone repository"
    COMPONENT_NOT_SUPPORTED = "Component not supported"
    REPOSITORY_NOT_FOUND = "Repository not found"

    # Error messages - Authentication
    INVALID_TOKEN = "Invalid token"
    TOKEN_EXPIRED = "Token has expired"
    NOT_AUTHENTICATED = "Not authenticated"
