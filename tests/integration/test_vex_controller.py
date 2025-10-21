import pytest


class TestVEXController:
    @pytest.mark.asyncio
    async def test_get_vexs_invalid_user_id(self, client):
        response = await client.get("/vex/user/invalid-id")

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_get_vex_by_id_invalid_id(self, client):
        response = await client.get("/vex/show/invalid-id")

        assert response.status_code == 422
