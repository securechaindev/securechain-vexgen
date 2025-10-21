import pytest


class TestTIXController:
    @pytest.mark.asyncio
    async def test_get_tixs_invalid_user_id(self, client):
        response = await client.get("/tix/user/invalid-id")

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_get_tix_by_id_invalid_id(self, client):
        response = await client.get("/tix/show/invalid-id")

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_download_tix_missing_body(self, client):
        response = await client.post("/tix/download")

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_download_tix_invalid_tix_id(self, client):
        response = await client.post(
            "/tix/download",
            json={"tix_id": "invalid-id"}
        )

        assert response.status_code == 422
