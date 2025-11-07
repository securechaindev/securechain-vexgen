import pytest


class TestTIXController:
    @pytest.mark.asyncio
    async def test_get_tix_by_id_invalid_id(self, client):
        response = await client.get("/tix/show/invalid-id")

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_download_tix_invalid_tix_id(self, client):
        response = await client.get("/tix/download/invalid-id")

        assert response.status_code == 422
