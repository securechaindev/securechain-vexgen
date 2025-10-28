
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import pytest
from git import GitCommandError, Repo

from app.domain.vex_generation.infrastructure.repository_downloader import (
    RepositoryDownloader,
)
from app.exceptions import CloneRepoException


class TestRepositoryDownloader:

    @pytest.fixture
    def downloader(self):
        return RepositoryDownloader()

    def test_initialization(self, downloader):
        assert downloader.base_directory == "repositories"
        assert downloader.git_config is not None
        assert downloader.clone_options is not None

    def test_prepare_directory_creates_new(self, downloader):
        with TemporaryDirectory() as temp_dir:
            test_dir = f"{temp_dir}/test_repo"

            downloader.prepare_directory(test_dir)

            assert Path(test_dir).exists()
            assert Path(test_dir).is_dir()

    def test_prepare_directory_removes_existing(self, downloader):
        with TemporaryDirectory() as temp_dir:
            test_dir = f"{temp_dir}/test_repo"
            Path(test_dir).mkdir()

            test_file = Path(test_dir) / "existing.txt"
            test_file.write_text("old content")

            downloader.prepare_directory(test_dir)

            assert Path(test_dir).exists()
            assert not test_file.exists()

    def test_prepare_directory_ignores_errors(self, downloader):
        with TemporaryDirectory() as temp_dir:
            test_dir = f"{temp_dir}/test_repo"

            downloader.prepare_directory(test_dir)
            assert Path(test_dir).exists()

    @patch('app.domain.vex_generation.infrastructure.repository_downloader.Repo')
    @patch('app.domain.vex_generation.infrastructure.repository_downloader.settings')
    def test_clone_repository_success(self, mock_settings, mock_repo_class, downloader):
        mock_settings.get_os_environment.return_value = {"GIT_TERMINAL_PROMPT": "0"}
        mock_repo = MagicMock(spec=Repo)
        mock_repo_class.clone_from.return_value = mock_repo

        url = "https://github.com/owner/repo.git"
        directory = "/tmp/test_repo"

        result = downloader.clone_repository(url, directory)

        assert result == mock_repo
        mock_repo_class.clone_from.assert_called_once_with(
            url,
            directory,
            env={"GIT_TERMINAL_PROMPT": "0"},
            multi_options=downloader.clone_options
        )

    @pytest.mark.asyncio
    @patch('app.domain.vex_generation.infrastructure.repository_downloader.Repo')
    @patch('app.domain.vex_generation.infrastructure.repository_downloader.settings')
    async def test_clone_repository_failure(self, mock_settings, mock_repo_class, downloader):
        mock_settings.get_os_environment.return_value = {}
        mock_repo_class.clone_from.side_effect = GitCommandError("clone", 1)

        url = "https://github.com/owner/repo.git"
        directory = "/tmp/test_repo"

        with pytest.raises(CloneRepoException):
            await downloader.clone_repository(url, directory)

    @patch('app.domain.vex_generation.infrastructure.repository_downloader.Path')
    def test_configure_repository_success(self, mock_path_class, downloader):
        mock_repo = MagicMock(spec=Repo)
        mock_repo.git.config = MagicMock()

        directory = "/tmp/test_repo"

        mock_empty_hooks = MagicMock()
        mock_empty_hooks.mkdir = MagicMock()
        mock_path_instance = MagicMock()
        mock_path_instance.__truediv__ = MagicMock(return_value=MagicMock(
            __truediv__=MagicMock(return_value=mock_empty_hooks)
        ))
        mock_path_class.return_value = mock_path_instance

        downloader.git_config = {
            "core.hooksPath": "/some/path",
            "user.name": "test",
            "user.email": "test@example.com"
        }

        downloader.configure_repository(mock_repo, directory)

        assert mock_repo.git.config.call_count == 3

    def test_configure_repository_creates_hooks_directory(self, downloader):
        with TemporaryDirectory() as temp_dir:
            git_dir = Path(temp_dir) / ".git"
            git_dir.mkdir()

            mock_repo = MagicMock(spec=Repo)
            mock_repo.git.config = MagicMock()

            downloader.git_config = {"user.name": "test"}

            downloader.configure_repository(mock_repo, temp_dir)

            hooks_dir = git_dir / "hooks-empty"
            assert hooks_dir.exists()
            assert hooks_dir.is_dir()

    @pytest.mark.asyncio
    async def test_configure_repository_failure(self, downloader):
        mock_repo = MagicMock(spec=Repo)
        mock_repo.git.config.side_effect = GitCommandError("config", 1)

        downloader.git_config = {"user.name": "test"}
        directory = "/tmp/test_repo"

        with pytest.raises(CloneRepoException):
            await downloader.configure_repository(mock_repo, directory)

    @patch('app.domain.vex_generation.infrastructure.repository_downloader.GitValidator')
    @pytest.mark.asyncio
    async def test_download_repository_validates_url(self, mock_validator, downloader):
        mock_validator.validate_git_url = MagicMock()

        with patch.object(downloader, 'prepare_directory'):
            with patch.object(downloader, 'clone_repository', side_effect=GitCommandError("clone", 1)):
                with pytest.raises(CloneRepoException):
                    await downloader.download_repository("owner", "repo")

        expected_url = "https://github.com/owner/repo.git"
        mock_validator.validate_git_url.assert_called_once_with(expected_url)

    @patch('app.domain.vex_generation.infrastructure.repository_downloader.GitValidator')
    @pytest.mark.asyncio
    async def test_download_repository_unique_directory(self, mock_validator, downloader):
        mock_validator.validate_git_url = MagicMock()

        with patch.object(downloader, 'prepare_directory') as mock_prepare:
            with patch.object(downloader, 'clone_repository', side_effect=GitCommandError("clone", 1)):
                try:
                    await downloader.download_repository("owner", "repo")
                except CloneRepoException:
                    pass

                call_arg = mock_prepare.call_args[0][0]
                assert call_arg.startswith("repositories/repo_")
                assert len(call_arg.split("_")[-1]) == 8

    @patch('app.domain.vex_generation.infrastructure.repository_downloader.GitValidator')
    @pytest.mark.asyncio
    async def test_download_repository_full_flow_success(self, mock_validator, downloader):
        mock_validator.validate_git_url = MagicMock()
        mock_repo = MagicMock(spec=Repo)

        with patch.object(downloader, 'prepare_directory') as mock_prepare:
            with patch.object(downloader, 'clone_repository', return_value=mock_repo) as mock_clone:
                with patch.object(downloader, 'configure_repository') as mock_config:
                    result = await downloader.download_repository("test-owner", "test-repo")

                    mock_prepare.assert_called_once()
                    mock_clone.assert_called_once()
                    mock_config.assert_called_once_with(mock_repo, result)

                    assert result.startswith("repositories/test-repo_")

    @patch('app.domain.vex_generation.infrastructure.repository_downloader.GitValidator')
    @pytest.mark.asyncio
    async def test_download_repository_clone_error(self, mock_validator, downloader):
        mock_validator.validate_git_url = MagicMock()

        with patch.object(downloader, 'prepare_directory'):
            with patch.object(downloader, 'clone_repository', side_effect=GitCommandError("clone", 128)):
                with pytest.raises(CloneRepoException):
                    await downloader.download_repository("owner", "repo")

    @patch('app.domain.vex_generation.infrastructure.repository_downloader.GitValidator')
    @pytest.mark.asyncio
    async def test_download_repository_config_error(self, mock_validator, downloader):
        mock_validator.validate_git_url = MagicMock()
        mock_repo = MagicMock(spec=Repo)

        with patch.object(downloader, 'prepare_directory'):
            with patch.object(downloader, 'clone_repository', return_value=mock_repo):
                with patch.object(downloader, 'configure_repository', side_effect=CloneRepoException()):
                    with pytest.raises(CloneRepoException):
                        await downloader.download_repository("owner", "repo")

    def test_configure_repository_hooks_path_special_handling(self, downloader):
        with TemporaryDirectory() as temp_dir:
            git_dir = Path(temp_dir) / ".git"
            git_dir.mkdir()

            mock_repo = MagicMock(spec=Repo)
            config_calls = []

            def track_config(key, value):
                config_calls.append((key, value))

            mock_repo.git.config.side_effect = track_config

            downloader.git_config = {
                "core.hooksPath": "/original/path",
                "user.name": "test"
            }

            downloader.configure_repository(mock_repo, temp_dir)

            hooks_path_call = next(call for call in config_calls if call[0] == "core.hooksPath")
            assert "hooks-empty" in str(hooks_path_call[1])

            user_name_call = next(call for call in config_calls if call[0] == "user.name")
            assert user_name_call[1] == "test"

    @patch('app.domain.vex_generation.infrastructure.repository_downloader.GitValidator')
    @pytest.mark.asyncio
    async def test_download_repository_multiple_calls_unique_dirs(self, mock_validator, downloader):
        mock_validator.validate_git_url = MagicMock()
        mock_repo = MagicMock(spec=Repo)

        directories = []

        with patch.object(downloader, 'prepare_directory'):
            with patch.object(downloader, 'clone_repository', return_value=mock_repo):
                with patch.object(downloader, 'configure_repository'):
                    for _ in range(3):
                        result = await downloader.download_repository("owner", "repo")
                        directories.append(result)

        assert len(set(directories)) == 3
        assert all(d.startswith("repositories/repo_") for d in directories)
