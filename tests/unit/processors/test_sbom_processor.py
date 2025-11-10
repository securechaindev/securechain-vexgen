
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, Mock, patch

import pytest
from pytz import UTC

from app.domain.vex_generation.processors.sbom_processor import SBOMProcessor
from app.exceptions import SbomNotFoundException
from app.schemas import GenerateVEXTIXRequest
from app.schemas.tix import TIXResponse
from app.schemas.vex import VEXResponse


class TestSBOMProcessor:

    @pytest.fixture
    def mock_github_service(self):
        service = AsyncMock()
        service.get_last_commit_date.return_value = datetime.now(UTC)
        return service

    @pytest.fixture
    def mock_vex_service(self):
        service = AsyncMock()
        service.read_vex_by_owner_name_sbom_name.return_value = None
        service.create_vex.return_value = "vex_id_123"
        service.update_user_vexs.return_value = None
        return service

    @pytest.fixture
    def mock_tix_service(self):
        service = AsyncMock()
        service.read_tix_by_owner_name_sbom_name.return_value = None
        service.create_tix.return_value = "tix_id_123"
        service.update_user_tixs.return_value = None
        return service

    @pytest.fixture
    def generate_request(self):
        return GenerateVEXTIXRequest(
            owner="test-owner",
            name="test-repo"
        )

    @pytest.fixture
    def processor(self, generate_request, mock_github_service, mock_vex_service, mock_tix_service):
        return SBOMProcessor(
            generate_request,
            mock_github_service,
            mock_vex_service,
            mock_tix_service,
            user_id="507f1f77bcf86cd799439011"
        )

    def test_initialization(self, processor, generate_request):
        assert processor.request == generate_request
        assert processor.sbom_file_extension == ".json"
        assert processor.sbom_identifier == "sbom"

    @pytest.mark.asyncio
    async def test_find_sbom_files_empty_directory(self, processor):
        result = await processor.find_sbom_files("/non/existent/path")
        assert result == []

    @pytest.mark.asyncio
    async def test_find_sbom_files_with_valid_sboms(self, processor):
        with TemporaryDirectory() as temp_dir:
            sbom1 = Path(temp_dir) / "sbom.json"
            sbom2 = Path(temp_dir) / "my-sbom-data.json"
            sbom3 = Path(temp_dir) / "SBOM_report.json"

            sbom_content = '{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}'
            sbom1.write_text(sbom_content)
            sbom2.write_text(sbom_content)
            sbom3.write_text(sbom_content)

            other = Path(temp_dir) / "other.json"
            other.write_text('{"data": "value"}')

            result = await processor.find_sbom_files(temp_dir)

            assert len(result) == 3
            assert all(str(Path(f)).endswith(".json") for f in result)
            assert all("sbom" in Path(f).name.lower() for f in result)

    @pytest.mark.asyncio
    async def test_find_sbom_files_case_insensitive(self, processor):
        with TemporaryDirectory() as temp_dir:
            sbom_content = '{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}'

            for name in ["SBOM.json", "Sbom.json", "sBom.json"]:
                file = Path(temp_dir) / name
                file.write_text(sbom_content)

            result = await processor.find_sbom_files(temp_dir)
            assert len(result) == 3

    @pytest.mark.asyncio
    async def test_find_sbom_files_nested_directories(self, processor):
        with TemporaryDirectory() as temp_dir:
            sbom_content = '{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}'

            nested = Path(temp_dir) / "subdir" / "deep"
            nested.mkdir(parents=True)

            sbom1 = Path(temp_dir) / "sbom.json"
            sbom2 = nested / "sbom.json"

            sbom1.write_text(sbom_content)
            sbom2.write_text(sbom_content)

            result = await processor.find_sbom_files(temp_dir)
            assert len(result) == 2

    @pytest.mark.asyncio
    async def test_is_cache_valid_no_cache(self, processor):
        result = await processor.is_cache_valid(None, datetime.now(UTC))
        assert result is False

    @pytest.mark.asyncio
    async def test_is_cache_valid_cache_newer(self, processor):
        commit_date = datetime.now(UTC) - timedelta(hours=2)
        cache_date = datetime.now(UTC) - timedelta(hours=1)

        last_vex = Mock(spec=VEXResponse)
        last_vex.moment = cache_date

        result = await processor.is_cache_valid(last_vex, commit_date)
        assert result is True

    @pytest.mark.asyncio
    async def test_is_cache_valid_cache_older(self, processor):
        commit_date = datetime.now(UTC) - timedelta(hours=1)
        cache_date = datetime.now(UTC) - timedelta(hours=2)

        last_vex = Mock(spec=VEXResponse)
        last_vex.moment = cache_date

        result = await processor.is_cache_valid(last_vex, commit_date)
        assert result is False

    @pytest.mark.asyncio
    async def test_is_cache_valid_same_time(self, processor):
        now = datetime.now(UTC)

        last_vex = Mock(spec=VEXResponse)
        last_vex.moment = now

        result = await processor.is_cache_valid(last_vex, now)
        assert result is True

    @pytest.mark.asyncio
    async def test_check_cached_vex_tix_no_cache(self, processor, mock_vex_service):
        sbom_files = ["/tmp/sbom.json"]
        directory = "/tmp"
        last_commit_date = datetime.now(UTC)

        mock_vex_service.read_vex_by_owner_name_sbom_name.return_value = None

        vex_list, tix_list, cached_paths = await processor.check_cached_vex_tix(
            sbom_files, directory, last_commit_date
        )

        assert vex_list == []
        assert tix_list == []
        assert cached_paths == []

    @pytest.mark.asyncio
    async def test_check_cached_vex_tix_with_valid_cache(self, processor, mock_vex_service, mock_tix_service):
        sbom_files = ["/tmp/repo/sbom.json"]
        directory = "/tmp/repo"
        last_commit_date = datetime.now(UTC) - timedelta(hours=2)

        cached_vex = Mock(spec=VEXResponse)
        cached_vex.id = "vex_id"
        cached_vex.moment = datetime.now(UTC) - timedelta(hours=1)
        cached_vex.model_dump = Mock(return_value={"_id": "vex_id", "statements": []})

        cached_tix = Mock(spec=TIXResponse)
        cached_tix.id = "tix_id"
        cached_tix.model_dump = Mock(return_value={"_id": "tix_id", "statements": []})

        mock_vex_service.read_vex_by_owner_name_sbom_name.return_value = cached_vex
        mock_tix_service.read_tix_by_owner_name_sbom_name.return_value = cached_tix

        vex_list, tix_list, cached_paths = await processor.check_cached_vex_tix(
            sbom_files, directory, last_commit_date
        )

        assert len(vex_list) == 1
        assert len(tix_list) == 1
        assert len(cached_paths) == 1
        mock_vex_service.update_user_vexs.assert_called_once_with("vex_id", "507f1f77bcf86cd799439011")

    @pytest.mark.asyncio
    async def test_save_vex_tix(self, processor, mock_vex_service, mock_tix_service):
        vex = {"statements": [{"id": "stmt1"}]}
        tix = {"statements": [{"id": "stmt2"}]}
        sbom_path = "path/to/sbom.json"

        await processor.save_vex_tix(vex, tix, sbom_path)

        mock_vex_service.create_vex.assert_called_once()
        vex_call = mock_vex_service.create_vex.call_args[0][0]
        assert vex_call.owner == "test-owner"
        assert vex_call.name == "test-repo"
        assert vex_call.sbom_path == sbom_path
        assert vex_call.sbom_name == "sbom.json"

        mock_tix_service.create_tix.assert_called_once()
        tix_call = mock_tix_service.create_tix.call_args[0][0]
        assert tix_call.owner == "test-owner"
        assert tix_call.name == "test-repo"
        assert tix_call.sbom_path == sbom_path
        assert tix_call.sbom_name == "sbom.json"

        mock_vex_service.update_user_vexs.assert_called_once_with("vex_id_123", "507f1f77bcf86cd799439011")
        mock_tix_service.update_user_tixs.assert_called_once_with("tix_id_123", "507f1f77bcf86cd799439011")

    @pytest.mark.asyncio
    async def test_save_vex_tix_nested_path(self, processor, mock_vex_service):
        vex = {"statements": []}
        tix = {"statements": []}
        sbom_path = "dir1/dir2/dir3/sbom.json"

        await processor.save_vex_tix(vex, tix, sbom_path)

        vex_call = mock_vex_service.create_vex.call_args[0][0]
        assert vex_call.sbom_name == "sbom.json"

    @pytest.mark.asyncio
    async def test_save_vex_tix_root_path(self, processor, mock_vex_service):
        vex = {"statements": []}
        tix = {"statements": []}
        sbom_path = "sbom.json"

        await processor.save_vex_tix(vex, tix, sbom_path)

        vex_call = mock_vex_service.create_vex.call_args[0][0]
        assert vex_call.sbom_name == "sbom.json"

    @pytest.mark.asyncio
    @patch('app.domain.vex_generation.processors.sbom_processor.RepositoryDownloader')
    async def test_process_sboms_no_sboms_found(self, mock_downloader_class, processor):
        mock_downloader = AsyncMock()
        mock_downloader.download_repository.return_value = "/tmp/repo"
        mock_downloader_class.return_value = mock_downloader

        with patch.object(processor, 'find_sbom_files', return_value=[]):
            with pytest.raises(SbomNotFoundException):
                await processor.process_sboms()

    @pytest.mark.asyncio
    @patch('app.domain.vex_generation.processors.sbom_processor.RepositoryDownloader')
    @patch('app.domain.vex_generation.processors.sbom_processor.VEXTIXInitializer')
    async def test_process_new_sboms(
        self,
        mock_initializer_class,
        mock_downloader_class,
        processor
    ):
        directory = "/tmp/repo"
        sboms_to_process = ["/tmp/repo/sbom.json"]

        mock_initializer = AsyncMock()
        mock_vex = {"statements": [{"id": "vex1"}]}
        mock_tix = {"statements": [{"id": "tix1"}]}
        mock_initializer.init_vex_tix.return_value = [(mock_vex, mock_tix)]
        mock_initializer_class.return_value = mock_initializer

        with patch.object(processor, 'save_vex_tix') as mock_save:
            vex_list, tix_list = await processor.process_new_sboms(sboms_to_process, directory)

            assert len(vex_list) == 1
            assert len(tix_list) == 1
            assert vex_list[0] == mock_vex
            assert tix_list[0] == mock_tix
            mock_save.assert_called_once()

    @pytest.mark.asyncio
    @patch('app.domain.vex_generation.processors.sbom_processor.RepositoryDownloader')
    @patch('app.domain.vex_generation.processors.sbom_processor.VEXTIXInitializer')
    @patch('app.domain.vex_generation.processors.sbom_processor.PathHelper')
    async def test_process_sboms_with_cache(
        self,
        mock_path_helper,
        mock_initializer_class,
        mock_downloader_class,
        processor,
        mock_github_service,
        mock_vex_service,
        mock_tix_service
    ):
        directory = "/tmp/repo"
        sbom_file = "/tmp/repo/sbom.json"

        mock_downloader = AsyncMock()
        mock_downloader.download_repository.return_value = directory
        mock_downloader_class.return_value = mock_downloader

        def mock_get_relative_path(file_path, base_dir):
            return "sbom.json"

        mock_path_helper.get_relative_path = mock_get_relative_path

        with patch.object(processor, 'find_sbom_files', return_value=[sbom_file]):
            cached_vex = Mock(spec=VEXResponse)
            cached_vex.id = "cached_vex_id"
            cached_vex.moment = datetime.now(UTC) + timedelta(hours=1)
            cached_vex.model_dump = Mock(return_value={"_id": "cached_vex_id", "statements": [{"id": "cached"}]})

            cached_tix = Mock(spec=TIXResponse)
            cached_tix.id = "cached_tix_id"
            cached_tix.model_dump = Mock(return_value={"_id": "cached_tix_id", "statements": [{"id": "cached"}]})

            mock_vex_service.read_vex_by_owner_name_sbom_name.return_value = cached_vex
            mock_tix_service.read_tix_by_owner_name_sbom_name.return_value = cached_tix

            result = await processor.process_sboms()

            assert len(result.vex_list) == 1
            assert len(result.tix_list) == 1
            assert len(result.sbom_paths) == 1
            assert result.directory == directory
            mock_vex_service.update_user_vexs.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_new_sboms_multiple_files(self, processor):
        directory = "/tmp/repo"
        sboms = ["/tmp/repo/sbom1.json", "/tmp/repo/sbom2.json"]

        mock_vex1 = {"statements": [{"id": "v1"}]}
        mock_tix1 = {"statements": [{"id": "t1"}]}
        mock_vex2 = {"statements": [{"id": "v2"}]}
        mock_tix2 = {"statements": [{"id": "t2"}]}

        with patch('app.domain.vex_generation.processors.sbom_processor.VEXTIXInitializer') as mock_init_class:
            mock_init = AsyncMock()
            mock_init.init_vex_tix.return_value = [
                (mock_vex1, mock_tix1),
                (mock_vex2, mock_tix2)
            ]
            mock_init_class.return_value = mock_init

            with patch.object(processor, 'save_vex_tix'):
                vex_list, tix_list = await processor.process_new_sboms(sboms, directory)

                assert len(vex_list) == 2
                assert len(tix_list) == 2
