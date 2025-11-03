import pytest


class TestHealthController:
    @pytest.mark.asyncio
    async def test_health_check(self, client):
        response = await client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["status"] == "healthy"
        assert "code" in data
        assert "message" in data
        assert data["code"] == "success_health_check"
        assert data["message"] == "API is healthy"

    @pytest.mark.asyncio
    async def test_health_check_returns_json(self, client):
        response = await client.get("/health")

        assert "application/json" in response.headers["content-type"]
        assert response.status_code == 200
