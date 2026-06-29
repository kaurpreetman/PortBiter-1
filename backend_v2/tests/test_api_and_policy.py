import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_api_app_importable():
    from backend_v2 import api

    assert hasattr(api, "app")


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
