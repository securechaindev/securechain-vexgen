import pytest


class TestVEXTIXController:
    @pytest.mark.asyncio
    async def test_generate_vex_tix_missing_body(self, client):
        response = await client.post("/vex_tix/generate")

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_generate_vex_tix_invalid_owner(self, client):
        response = await client.post(
            "/vex_tix/generate",
            json={
                "owner": "",
                "name": "repo-name",
                "user_id": "507f1f77bcf86cd799439011"
            }
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_generate_vex_tix_invalid_repo_name(self, client):
        response = await client.post(
            "/vex_tix/generate",
            json={
                "owner": "test-owner",
                "name": "",
                "user_id": "507f1f77bcf86cd799439011"
            }
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_generate_vex_tix_missing_owner(self, client):
        response = await client.post(
            "/vex_tix/generate",
            json={
                "name": "repo-name",
                "user_id": "507f1f77bcf86cd799439011"
            }
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_generate_vex_tix_invalid_user_id(self, client):
        response = await client.post(
            "/vex_tix/generate",
            json={
                "owner": "test-owner",
                "name": "repo-name",
                "user_id": "invalid-id"
            }
        )

        assert response.status_code == 422
