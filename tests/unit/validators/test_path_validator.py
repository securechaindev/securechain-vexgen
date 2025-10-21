from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from app.validators import PathValidator


class TestPathValidator:

    def test_sanitize_path_valid(self):
        path = "/tmp/test/file.json"
        result = PathValidator.sanitize_path(path)
        assert isinstance(result, Path)

    def test_sanitize_path_empty_string(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.sanitize_path("")
        assert exc.value.args[0] == "File path is required and must be a string"

    def test_sanitize_path_none(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.sanitize_path(None)
        assert exc.value.args[0] == "File path is required and must be a string"

    def test_sanitize_path_not_string(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.sanitize_path(123)
        assert exc.value.args[0] == "File path is required and must be a string"

    def test_sanitize_path_dangerous_double_dot(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.sanitize_path("/tmp/../etc/passwd")
        assert "Path contains dangerous component" in exc.value.args[0]

    def test_sanitize_path_dangerous_tilde(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.sanitize_path("~/malicious")
        assert "Path contains dangerous component" in exc.value.args[0]

    def test_sanitize_path_null_byte(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.sanitize_path("/tmp/file\0malicious")
        assert exc.value.args[0] == "Path contains null bytes"

    def test_sanitize_path_strips_whitespace(self):
        path = "  /tmp/test/file.json  "
        result = PathValidator.sanitize_path(path)
        assert isinstance(result, Path)

    def test_sanitize_path_with_base_dir_valid(self):
        with TemporaryDirectory() as tmpdir:
            file_path = f"{tmpdir}/subdir/file.json"
            result = PathValidator.sanitize_path(file_path, tmpdir)
            assert isinstance(result, Path)

    def test_sanitize_path_with_base_dir_traversal_attempt(self):
        with TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError) as exc:
                PathValidator.sanitize_path("/etc/passwd", tmpdir)
            assert "Path contains dangerous component" in exc.value.args[0] or "Path traversal attempt detected" in exc.value.args[0]

    def test_validate_sbom_file_valid_json(self):
        path = "/tmp/sbom.json"
        result = PathValidator.validate_sbom_file(path)
        assert isinstance(result, Path)

    def test_validate_sbom_file_valid_xml(self):
        path = "/tmp/sbom.xml"
        result = PathValidator.validate_sbom_file(path)
        assert isinstance(result, Path)

    def test_validate_sbom_file_valid_spdx(self):
        path = "/tmp/sbom.spdx"
        result = PathValidator.validate_sbom_file(path)
        assert isinstance(result, Path)

    def test_validate_sbom_file_invalid_extension(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.validate_sbom_file("/tmp/sbom.txt")
        assert "Invalid SBOM file extension" in exc.value.args[0]

    def test_validate_sbom_file_no_extension(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.validate_sbom_file("/tmp/sbom")
        assert "Invalid SBOM file extension" in exc.value.args[0]

    def test_validate_filename_valid(self):
        filename = "my-file.json"
        result = PathValidator.validate_filename(filename)
        assert result == filename

    def test_validate_filename_empty(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.validate_filename("")
        assert exc.value.args[0] == "Filename is required"

    def test_validate_filename_none(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.validate_filename(None)
        assert exc.value.args[0] == "Filename is required"

    def test_validate_filename_with_slash(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.validate_filename("path/to/file.json")
        assert exc.value.args[0] == "Filename must not contain path separators"

    def test_validate_filename_with_backslash(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.validate_filename("path\\to\\file.json")
        assert exc.value.args[0] == "Filename must not contain path separators"

    def test_validate_filename_dangerous_double_dot(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.validate_filename("..malicious")
        assert exc.value.args[0] == "Filename contains invalid characters"

    def test_validate_filename_dangerous_tilde(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.validate_filename("~malicious")
        assert exc.value.args[0] == "Filename contains invalid characters"

    def test_validate_filename_dangerous_null_byte(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.validate_filename("file\0malicious")
        assert exc.value.args[0] == "Filename contains invalid characters"

    def test_validate_filename_too_long(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.validate_filename("a" * 256)
        assert exc.value.args[0] == "Filename too long (max 255 characters)"

    def test_validate_filename_strips_whitespace(self):
        filename = "  my-file.json  "
        result = PathValidator.validate_filename(filename)
        assert result == filename.strip()

    def test_validate_filename_custom_context(self):
        with pytest.raises(ValueError) as exc:
            PathValidator.validate_filename("", context="Custom Field")
        assert exc.value.args[0] == "Custom Field is required"
