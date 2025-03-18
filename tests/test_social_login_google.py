import pytest
import httpx
from fastapi import status
from fastapi.testclient import TestClient

from j_user_auth_svc.models.user import User

# Note: We rely on the fixtures from conftest.py: client and db_session

# Test case: Successful Google social login

def test_successful_google_login(client, db_session, monkeypatch):
    # Monkeypatch validate_social_token to simulate a valid Google response with email
    async def fake_validate_social_token(provider, access_token):
        return {"email": "success@example.com"}

    monkeypatch.setattr("j_user_auth_svc.routers.login.validate_social_token", fake_validate_social_token)

    # Setup: create a user with the expected email and sentinel hashed_password for Google social login
    session = db_session
    user = User(email="success@example.com", hashed_password="google_social")
    session.add(user)
    session.commit()

    response = client.post("/login/google", json={"access_token": "dummy_token"})
    assert response.status_code == 200
    data = response.json()
    assert "session_token" in data
    assert isinstance(data["session_token"], str) and len(data["session_token"]) > 0


# Test case: Missing access_token field resulting in a Pydantic validation error (HTTP 422)

def test_missing_access_token(client):
    response = client.post("/login/google", json={})
    assert response.status_code == 422


# Test case: Invalid token response (missing email in token data)

def test_invalid_token_missing_email(client, monkeypatch):
    async def fake_validate_social_token(provider, access_token):
        # Simulate token response without email
        return {}

    monkeypatch.setattr("j_user_auth_svc.routers.login.validate_social_token", fake_validate_social_token)

    response = client.post("/login/google", json={"access_token": "invalid_token"})
    assert response.status_code == 401
    assert "Email not found" in response.json().get("detail", "")


# Test case: Simulated network error during token validation

def test_network_error(monkeypatch, client):
    from httpx import RequestError
    async def fake_validate_social_token(provider, access_token):
        raise RequestError("Simulated network error")

    monkeypatch.setattr("j_user_auth_svc.routers.login.validate_social_token", fake_validate_social_token)

    response = client.post("/login/google", json={"access_token": "any_token"})
    # Expecting HTTP 500 due to network error caught and converted
    assert response.status_code == 500


# Test case: Provider mismatch: user exists but not registered via Google social login

def test_provider_mismatch(client, db_session, monkeypatch):
    async def fake_validate_social_token(provider, access_token):
        return {"email": "mismatch@example.com"}

    monkeypatch.setattr("j_user_auth_svc.routers.login.validate_social_token", fake_validate_social_token)

    # Setup: create a user with an email but with a non-sentinel hashed_password
    session = db_session
    user = User(email="mismatch@example.com", hashed_password="regular_password_hash")
    session.add(user)
    session.commit()

    response = client.post("/login/google", json={"access_token": "dummy_token"})
    assert response.status_code == 401
    assert "Provider mismatch" in response.json().get("detail", "")
