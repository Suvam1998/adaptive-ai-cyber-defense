"""Deployment-readiness tests: health, root, docs, no localhost API dependency."""
from pathlib import Path

from fastapi.testclient import TestClient

from backend.config import config
from backend.main import app

client = TestClient(app)
ROOT = Path(__file__).resolve().parent.parent


def test_health_returns_200():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_root_serves_app():
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")


def test_openapi_docs_available():
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


def test_frontend_has_no_hardcoded_localhost_api():
    for name in ("app.js", "index.html"):
        text = (ROOT / "frontend" / name).read_text(encoding="utf-8")
        assert "http://127.0.0.1" not in text
        assert "http://localhost" not in text


def test_safe_response_defaults_hold():
    assert config.RESPONSE_SIMULATION is True
    assert config.AUTO_RESPONSE_ENABLED is False
    r = client.get("/api/config").json()
    assert r["response_simulation"] is True
    assert r["auto_response_enabled"] is False


def test_deployment_files_present_and_use_port_env():
    proc = (ROOT / "Procfile").read_text(encoding="utf-8")
    assert "0.0.0.0" in proc and "$PORT" in proc
    render = (ROOT / "render.yaml").read_text(encoding="utf-8")
    assert "0.0.0.0" in render and "$PORT" in render
    assert (ROOT / ".env.example").exists()
