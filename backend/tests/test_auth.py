import pytest
from main import app
from auth import verify_token, verify_token_string


def test_protected_endpoint_rejects_missing_token(client):
    """Temporarily removes the test's fake-auth override to confirm the real
    dependency actually rejects requests with no Authorization header."""
    original_override = app.dependency_overrides.pop(verify_token, None)
    try:
        response = client.get("/threat-intel/history")
        assert response.status_code in (401, 403)
    finally:
        if original_override is not None:
            app.dependency_overrides[verify_token] = original_override


def test_verify_token_string_rejects_garbage_token():
    with pytest.raises(ValueError):
        verify_token_string("not.a.real.jwt")


def test_verify_token_string_rejects_empty_token():
    with pytest.raises(ValueError):
        verify_token_string("")


def test_health_and_root_do_not_require_auth(client):
    """These two endpoints have no Depends(verify_token), so they should
    work even with the auth override removed."""
    original_override = app.dependency_overrides.pop(verify_token, None)
    try:
        assert client.get("/").status_code == 200
        assert client.get("/health").status_code == 200
    finally:
        if original_override is not None:
            app.dependency_overrides[verify_token] = original_override