from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from app.domain.vex_generation.helpers.path_helper import PathHelper


@pytest.mark.asyncio
class TestPathHelper:

    async def test_get_relative_path_simple(self):
        with TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()
            file_path = subdir / "file.txt"
            file_path.touch()

            result = await PathHelper.get_relative_path(str(file_path), tmpdir)

            assert result == "subdir/file.txt" or result == "subdir\\file.txt"

    async def test_get_relative_path_nested(self):
        with TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "level1" / "level2" / "level3"
            nested.mkdir(parents=True)
            file_path = nested / "deep.txt"
            file_path.touch()

            result = await PathHelper.get_relative_path(str(file_path), tmpdir)

            assert "level1" in result
            assert "level2" in result
            assert "level3" in result
            assert "deep.txt" in result

    async def test_get_relative_path_same_dir(self):
        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "file.txt"
            file_path.touch()

            result = await PathHelper.get_relative_path(str(file_path), tmpdir)

            assert result == "file.txt"

    async def test_get_relative_path_sanitizes(self):
        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.txt"
            file_path.touch()

            result = await PathHelper.get_relative_path(str(file_path), tmpdir)

            assert isinstance(result, str)
            assert ".." not in result
