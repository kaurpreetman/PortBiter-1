import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_api_app_importable():
    from backend_v2 import api

    assert hasattr(api, "app")


def test_api_allows_deployed_frontend_origin():
    from fastapi.testclient import TestClient
    from backend_v2.api import app

    response = TestClient(app).options(
        "/scans",
        headers={
            "Origin": "https://port-biter-front.vercel.app",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://port-biter-front.vercel.app"


def test_policy_allows_loopback_when_env_set(monkeypatch):
    monkeypatch.setenv("ALLOW_LOCALHOST", "true")
    from backend_v2.policy.engine import validate

    # Should not raise
    validate("http://127.0.0.1/")


def test_policy_blocks_loopback_by_default(monkeypatch):
    monkeypatch.delenv("ALLOW_LOCALHOST", raising=False)
    from backend_v2.policy.engine import validate, PolicyViolationError
    import pytest

    with pytest.raises(PolicyViolationError):
        validate("http://127.0.0.1/")
