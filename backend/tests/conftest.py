import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient
from main import app
from auth import verify_token

# Fake user — overrides real Keycloak JWT verification during tests
def fake_verify_token():
    return {"preferred_username": "test_user", "sub": "test-id", "realm_access": {"roles": ["analyst"]}}

app.dependency_overrides[verify_token] = fake_verify_token

@pytest.fixture
def client():
    return TestClient(app)