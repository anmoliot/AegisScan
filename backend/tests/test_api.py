import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.scanner.target_policy import ValidatedTarget


def test_auth_and_protected_plugin_catalog():
    email = f"test-{uuid.uuid4()}@example.com"
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        response = client.post("/api/v1/auth/register", json={"email": email, "password": "A-secure-test-password-123"})
        assert response.status_code == 201, response.text
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
        plugins = client.get("/api/v1/scans/plugins", headers=headers)
        assert plugins.status_code == 200
        assert len(plugins.json()) == 6
        refreshed = client.post("/api/v1/auth/refresh")
        assert refreshed.status_code == 200, refreshed.text


def test_deployed_frontend_cors_preflight_is_allowed():
    with TestClient(app) as client:
        for origin in (
            "https://adaptivescan-mocha.vercel.app",
            "https://adaptivescan-jz67t5kn9-anmoliots-projects.vercel.app",
            "https://adaptivescan-feature-login-anmoliots-projects.vercel.app",
        ):
            response = client.options("/api/v1/auth/login", headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            })
            assert response.status_code == 200, response.text
            assert response.headers["access-control-allow-origin"] == origin
            assert response.headers["access-control-allow-credentials"] == "true"


def test_scan_creation_is_authorized_and_queued(monkeypatch):
    class DummyExecutor:
        def submit(self, scan_id):
            assert scan_id

    async def approved_target(_):
        return ValidatedTarget("https://example.com/", "example.com")

    monkeypatch.setattr("app.scans.router.validate_target", approved_target)
    monkeypatch.setattr("app.scans.router.get_executor", lambda: DummyExecutor())
    email = f"test-{uuid.uuid4()}@example.com"
    with TestClient(app) as client:
        token = client.post("/api/v1/auth/register", json={
            "email": email, "password": "A-secure-test-password-123"
        }).json()["access_token"]
        response = client.post("/api/v1/scans", headers={"Authorization": f"Bearer {token}"}, json={
            "target_url": "https://example.com/", "authorization_confirmed": True,
            "enabled_plugins": ["security_headers"],
        })
        assert response.status_code == 202, response.text
        assert response.json()["status"] == "queued"
