
import json
from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock, patch

import pytest

from app.domain.vex_generation.processors.vex_tix_initializer import VEXTIXInitializer


class TestVEXTIXInitializer:

    @pytest.fixture
    def initializer(self):
        return VEXTIXInitializer(directory="/tmp/test")

    @pytest.fixture
    def valid_sbom(self):
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "name": "express",
                    "version": "4.18.0",
                    "purl": "pkg:npm/express@4.18.0"
                }
            ]
        }

    def test_initialization(self, initializer):
        assert initializer.directory == "/tmp/test"
        assert initializer.sbom_components_key == "components"

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_load_sbom_file(self, initializer, valid_sbom):
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(valid_sbom, f)
            f.flush()

            result = await initializer.load_sbom_file(f.name)

            assert result == valid_sbom
            assert "components" in result
            assert len(result["components"]) == 1

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_load_sbom_file_not_found(self, initializer):
        with pytest.raises(FileNotFoundError):
            await initializer.load_sbom_file("/non/existent/file.json")

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_load_sbom_file_invalid_json(self, initializer):
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid json")
            f.flush()

            with pytest.raises(json.JSONDecodeError):
                await initializer.load_sbom_file(f.name)

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_validate_sbom_structure_valid(self, initializer, valid_sbom):
        result = await initializer.validate_sbom_structure(valid_sbom)
        assert result is True

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_validate_sbom_structure_not_dict(self, initializer):
        result = await initializer.validate_sbom_structure([])
        assert result is False

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_validate_sbom_structure_missing_components(self, initializer):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4"
        }
        result = await initializer.validate_sbom_structure(sbom)
        assert result is False

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_validate_sbom_structure_components_not_list(self, initializer):
        sbom = {
            "components": "not a list"
        }
        result = await initializer.validate_sbom_structure(sbom)
        assert result is False

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_validate_sbom_structure_empty_components(self, initializer):
        sbom = {
            "components": []
        }
        result = await initializer.validate_sbom_structure(sbom)
        assert result is True

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_validate_sbom_structure_none(self, initializer):
        result = await initializer.validate_sbom_structure(None)
        assert result is False

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_validate_sbom_structure_string(self, initializer):
        result = await initializer.validate_sbom_structure("not a dict")
        assert result is False

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_process_single_sbom_complete(self, initializer, valid_sbom):
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(valid_sbom, f)
            f.flush()

            with patch('app.domain.vex_generation.processors.vex_tix_initializer.create_vex_template') as mock_vex:
                with patch('app.domain.vex_generation.processors.vex_tix_initializer.create_tix_template') as mock_tix:
                    with patch('app.domain.vex_generation.processors.vex_tix_initializer.StatementHelpers.set_timestamps') as mock_timestamps:
                        with patch('app.domain.vex_generation.processors.vex_tix_initializer.StatementsGenerator') as mock_gen_class:
                            mock_vex.return_value = {"statements": []}
                            mock_tix.return_value = {"statements": []}
                            mock_timestamps.return_value = None

                            mock_gen = AsyncMock()
                            mock_gen.generate_statements.return_value = (
                                {"author": "test-owner", "statements": [{"vuln": "CVE-1"}]},
                                {"author": "test-owner", "statements": [{"vuln": "CVE-1"}]}
                            )
                            mock_gen_class.return_value = mock_gen

                            vex, tix = await initializer.process_single_sbom(
                                f.name,
                                "test-owner",
                                "2024-01-01T00:00:00Z"
                            )

                            assert "author" in vex
                            assert vex["author"] == "test-owner"
                            assert "author" in tix
                            assert tix["author"] == "test-owner"

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_process_single_sbom_invalid_structure(self, initializer):
        invalid_sbom = {"invalid": "structure"}

        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(invalid_sbom, f)
            f.flush()

            with pytest.raises(ValueError, match="Invalid SBOM structure"):
                await initializer.process_single_sbom(
                    f.name,
                    "test-owner",
                    "2024-01-01T00:00:00Z"
                )

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_process_single_sbom_sets_author(self, initializer, valid_sbom):
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(valid_sbom, f)
            f.flush()

            with patch('app.domain.vex_generation.processors.vex_tix_initializer.create_vex_template') as mock_vex:
                with patch('app.domain.vex_generation.processors.vex_tix_initializer.create_tix_template') as mock_tix:
                    with patch('app.domain.vex_generation.processors.vex_tix_initializer.StatementHelpers.set_timestamps'):
                        with patch('app.domain.vex_generation.processors.vex_tix_initializer.StatementsGenerator') as mock_gen_class:
                            vex_template = {"statements": []}
                            tix_template = {"statements": []}
                            mock_vex.return_value = vex_template
                            mock_tix.return_value = tix_template

                            mock_gen = AsyncMock()
                            mock_gen.generate_statements.return_value = (vex_template, tix_template)
                            mock_gen_class.return_value = mock_gen

                            vex, tix = await initializer.process_single_sbom(
                                f.name,
                                "custom-owner",
                                "2024-01-01T00:00:00Z"
                            )

                            assert vex["author"] == "custom-owner"
                            assert tix["author"] == "custom-owner"

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_init_vex_tix_single_sbom(self, initializer, valid_sbom):
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(valid_sbom, f)
            f.flush()

            with patch.object(initializer, 'process_single_sbom') as mock_process:
                mock_process.return_value = (
                    {"statements": [{"vuln": "CVE-1"}]},
                    {"statements": [{"vuln": "CVE-1"}]}
                )

                results = await initializer.init_vex_tix("test-owner", [f.name])

                assert len(results) == 1
                assert isinstance(results[0], tuple)
                assert len(results[0]) == 2
                mock_process.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_init_vex_tix_multiple_sboms(self, initializer, valid_sbom):
        files = []
        for _ in range(3):
            with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(valid_sbom, f)
                f.flush()
                files.append(f.name)

        with patch.object(initializer, 'process_single_sbom') as mock_process:
            mock_process.return_value = (
                {"statements": []},
                {"statements": []}
            )

            results = await initializer.init_vex_tix("test-owner", files)

            assert len(results) == 3
            assert mock_process.call_count == 3

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_init_vex_tix_empty_list(self, initializer):
        results = await initializer.init_vex_tix("test-owner", [])

        assert len(results) == 0
        assert isinstance(results, list)

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_init_vex_tix_generates_timestamp(self, initializer, valid_sbom):
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(valid_sbom, f)
            f.flush()

            with patch.object(initializer, 'process_single_sbom') as mock_process:
                mock_process.return_value = ({"statements": []}, {"statements": []})

                await initializer.init_vex_tix("test-owner", [f.name])

                call_args = mock_process.call_args[0]
                timestamp = call_args[2]
                assert "T" in timestamp
                assert timestamp.endswith("Z") or "+" in timestamp

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_process_single_sbom_calls_statement_generator(self, initializer, valid_sbom):
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(valid_sbom, f)
            f.flush()

            with patch('app.domain.vex_generation.processors.vex_tix_initializer.create_vex_template') as mock_vex:
                with patch('app.domain.vex_generation.processors.vex_tix_initializer.create_tix_template') as mock_tix:
                    with patch('app.domain.vex_generation.processors.vex_tix_initializer.StatementHelpers.set_timestamps'):
                        with patch('app.domain.vex_generation.processors.vex_tix_initializer.StatementsGenerator') as mock_gen_class:
                            mock_vex.return_value = {"statements": []}
                            mock_tix.return_value = {"statements": []}

                            mock_gen = AsyncMock()
                            mock_gen.generate_statements.return_value = ({"statements": []}, {"statements": []})
                            mock_gen_class.return_value = mock_gen

                            await initializer.process_single_sbom(
                                f.name,
                                "test-owner",
                                "2024-01-01T00:00:00Z"
                            )

                            mock_gen_class.assert_called_once_with("/tmp/test")

                            mock_gen.generate_statements.assert_called_once()
                            call_args = mock_gen.generate_statements.call_args[0]
                            assert call_args[0] == valid_sbom["components"]
                            assert call_args[1] == "2024-01-01T00:00:00Z"

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_process_single_sbom_calls_set_timestamps(self, initializer, valid_sbom):
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(valid_sbom, f)
            f.flush()

            with patch('app.domain.vex_generation.processors.vex_tix_initializer.create_vex_template') as mock_vex:
                with patch('app.domain.vex_generation.processors.vex_tix_initializer.create_tix_template') as mock_tix:
                    with patch('app.domain.vex_generation.processors.vex_tix_initializer.StatementHelpers.set_timestamps') as mock_timestamps:
                        with patch('app.domain.vex_generation.processors.vex_tix_initializer.StatementsGenerator') as mock_gen_class:
                            vex_template = {"statements": []}
                            tix_template = {"statements": []}
                            mock_vex.return_value = vex_template
                            mock_tix.return_value = tix_template

                            mock_gen = AsyncMock()
                            mock_gen.generate_statements.return_value = (vex_template, tix_template)
                            mock_gen_class.return_value = mock_gen

                            await initializer.process_single_sbom(
                                f.name,
                                "test-owner",
                                "2024-01-01T00:00:00Z"
                            )

                            assert mock_timestamps.call_count == 2

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_load_sbom_file_with_unicode(self, initializer):
        sbom_with_unicode = {
            "components": [
                {
                    "name": "paquete-español",
                    "version": "1.0.0",
                    "description": "Descripción con acentos"
                }
            ]
        }

        with NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(sbom_with_unicode, f, ensure_ascii=False)
            f.flush()

            result = await initializer.load_sbom_file(f.name)

            assert result == sbom_with_unicode
            assert "español" in result["components"][0]["name"]

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_init_vex_tix_preserves_order(self, initializer, valid_sbom):
        files = []
        for _ in range(3):
            with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(valid_sbom, f)
                f.flush()
                files.append(f.name)

        with patch.object(initializer, 'process_single_sbom') as mock_process:
            mock_process.side_effect = [
                ({"id": 1}, {"id": 1}),
                ({"id": 2}, {"id": 2}),
                ({"id": 3}, {"id": 3})
            ]

            results = await initializer.init_vex_tix("test-owner", files)

            assert results[0][0]["id"] == 1
            assert results[1][0]["id"] == 2
            assert results[2][0]["id"] == 3
