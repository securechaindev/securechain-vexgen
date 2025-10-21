import pytest


class TestHealthController:
    @pytest.mark.asyncio
    async def test_health_check(self, client):
        response = await client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "detail" in data

    @pytest.mark.asyncio
    async def test_health_check_returns_json(self, client):
        response = await client.get("/health")

        assert "application/json" in response.headers["content-type"]
        assert response.status_code == 200
