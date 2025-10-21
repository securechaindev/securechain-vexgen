from enum import Enum


class HTTPStatusMessage(str, Enum):
    # Success messages
    SUCCESS_VEXS_RETRIEVED = "success_vexs_retrieved"
    SUCCESS_VEX_RETRIEVED = "success_vex_retrieved"
    SUCCESS_TIXS_RETRIEVED = "success_tixs_retrieved"
    SUCCESS_TIX_RETRIEVED = "success_tix_retrieved"
    SUCCESS_VEX_GENERATED = "success_vex_generated"
    SUCCESS_TIX_GENERATED = "success_tix_generated"
    SUCCESS_HEALTH_CHECK = "success_health_check"

    # Error messages - General
    VALIDATION_ERROR = "validation_error"
    HTTP_ERROR = "http_error"
    INTERNAL_ERROR = "internal_error"
    NOT_FOUND = "not_found"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"

    # Error messages - VEX/TIX specific
    ERROR_VEX_NOT_FOUND = "error_vex_not_found"
    ERROR_TIX_NOT_FOUND = "error_tix_not_found"

    # Error messages - SBOM
    INVALID_SBOM = "invalid_sbom"
    SBOM_NOT_FOUND = "sbom_not_found"

    # Error messages - Repository
    INVALID_REPOSITORY = "invalid_repository"
    CLONE_REPO_ERROR = "clone_repo_error"
    COMPONENT_NOT_SUPPORTED = "component_not_supported"

    # Error messages - Authentication
    INVALID_TOKEN = "invalid_token"
    EXPIRED_TOKEN = "expired_token"
