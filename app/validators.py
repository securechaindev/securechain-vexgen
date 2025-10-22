from pathlib import Path
from urllib.parse import urlparse

from regex import match

from app.constants import FileRules, GitRules


class GitValidator:
    @staticmethod
    def validate_git_url(url: str) -> str:
        if not url or not isinstance(url, str):
            raise ValueError("Repository URL is required and must be a string")

        url = url.strip()

        url_lower = url.lower()
        for dangerous_pattern in GitRules.DANGEROUS_URL_PATTERNS:
            if dangerous_pattern in url_lower:
                raise ValueError(f"Dangerous URL scheme detected: {dangerous_pattern}")

        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL format: {e!s}") from e

        if parsed.scheme not in ("https", "http"):
            raise ValueError("Only HTTPS/HTTP URLs are allowed for Git repositories")

        if parsed.netloc not in GitRules.ALLOWED_GIT_HOSTS:
            raise ValueError(f"Git host not allowed. Allowed hosts: {', '.join(GitRules.ALLOWED_GIT_HOSTS)}")

        if "github.com" in parsed.netloc:
            if not GitValidator._is_valid_github_url(url):
                raise ValueError("Invalid GitHub repository URL format")

        dangerous_chars = ['`', '$', ';', '|', '&', '\n', '\r', '\0']
        if any(char in url for char in dangerous_chars):
            raise ValueError("URL contains potentially dangerous characters")

        return url

    @staticmethod
    def _is_valid_github_url(url: str) -> bool:
        github_pattern = r"^https://github\.com/[\w\-]+/[\w\-\.]+(?:\.git)?$"
        return bool(match(github_pattern, url))

    @staticmethod
    def validate_branch_name(branch: str) -> str:
        if not branch or not isinstance(branch, str):
            raise ValueError("Branch name is required")

        branch = branch.strip()

        dangerous_chars = ['`', '$', ';', '|', '&', '\n', '\r', '\0', '..', '~']
        if any(char in branch for char in dangerous_chars):
            raise ValueError("Branch name contains invalid characters")

        if branch.startswith('-') or branch.endswith('.') or '..' in branch:
            raise ValueError("Invalid branch name format")

        return branch

    @staticmethod
    def validate_repository_component(component: str) -> str:
        if not component or not isinstance(component, str):
            raise ValueError("Repository component is required")

        component = component.strip()

        dangerous_chars = ['`', '$', ';', '|', '&', '\n', '\r', '\0', '..', '/', '\\', '~']
        if any(char in component for char in dangerous_chars):
            raise ValueError("Repository component contains invalid characters")

        if not match(r'^[\w\-\.]+$', component):
            raise ValueError("Repository component must contain only alphanumeric characters, hyphens, underscores, and dots")

        return component


class PathValidator:
    @staticmethod
    def sanitize_path(file_path: str, base_dir: str | None = None) -> Path:
        if not file_path or not isinstance(file_path, str):
            raise ValueError("File path is required and must be a string")

        file_path = file_path.strip()

        for dangerous in FileRules.DANGEROUS_PATH_COMPONENTS:
            if dangerous in file_path:
                raise ValueError(f"Path contains dangerous component: {dangerous}")

        if '\0' in file_path:
            raise ValueError("Path contains null bytes")

        try:
            path = Path(file_path).resolve()
        except Exception as e:
            raise ValueError(f"Invalid path format: {e!s}") from e

        if base_dir:
            try:
                base = Path(base_dir).resolve()
                path.relative_to(base)
            except ValueError as e:
                raise ValueError(f"Path traversal attempt detected: path must be within {base_dir}") from e

        return path

    @staticmethod
    def validate_sbom_file(file_path: str) -> Path:
        path = PathValidator.sanitize_path(file_path)

        if path.suffix.lower() not in FileRules.ALLOWED_SBOM_EXTENSIONS:
            raise ValueError(
                f"Invalid SBOM file extension. Allowed: {', '.join(FileRules.ALLOWED_SBOM_EXTENSIONS)}"
            )

        return path

    @staticmethod
    def validate_filename(filename: str, context: str = "Filename") -> str:
        if not filename or not isinstance(filename, str):
            raise ValueError(f"{context} is required")

        filename = filename.strip()

        if '/' in filename or '\\' in filename:
            raise ValueError(f"{context} must not contain path separators")

        dangerous_chars = ['..', '~', '\0', '\n', '\r', '|', '&', ';', '`', '$']
        if any(char in filename for char in dangerous_chars):
            raise ValueError(f"{context} contains invalid characters")

        if len(filename) > 255:
            raise ValueError(f"{context} too long (max 255 characters)")

        return filename
