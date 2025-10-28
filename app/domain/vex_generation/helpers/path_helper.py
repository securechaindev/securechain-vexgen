from os.path import relpath

from app.validators import PathValidator


class PathHelper:
    @staticmethod
    def get_relative_path(file_path: str, base_dir: str) -> str:
        sanitized_path = PathValidator.sanitize_path(file_path, base_dir)
        return relpath(str(sanitized_path), base_dir)
