import pytest
from fastapi import status
from httpx import RequestError

from fastapi.testclient import TestClient
from j_user_auth_svc.models.user import User


def test_successful_twitter_login(client, db_session, monkeypatch):
    async def fake_validate_social_token(provider, access_token):
        return {"email": "twitter_success@example.com"}

    monkeypatch.setattr("j_user_auth_svc.routers.login.validate_social_token", fake_validate_social_token)

    session = db_session
    user = User(email="twitter_success@example.com", hashed_password="twitter_social")
    session.add(user)
    session.commit()

    response = client.post("/login/twitter", json={"access_token": "dummy_token"})
    assert response.status_code == 200
    data = response.json()
    assert "session_token" in data
    assert isinstance(data["session_token"], str) and len(data["session_token"]) > 0


def test_missing_access_token(client):
    response = client.post("/login/twitter", json={})
    assert response.status_code == 422


def test_invalid_token_missing_identifier(monkeypatch, client):
    async def fake_validate_social_token(provider, access_token):
        # Simulate token response without identifier
        return {}

    monkeypatch.setattr("j_user_auth_svc.routers.login.validate_social_token", fake_validate_social_token)
    response = client.post("/login/twitter", json={"access_token": "invalid_token"})
    assert response.status_code == 401
    assert "Identifier not found" in response.json().get("detail", "")


def test_network_error(monkeypatch, client):
    async def fake_validate_social_token(provider, access_token):
        raise RequestError("Simulated network error")

    monkeypatch.setattr("j_user_auth_svc.routers.login.validate_social_token", fake_validate_social_token)
    response = client.post("/login/twitter", json={"access_token": "any_token"})
    assert response.status_code == 500


def test_provider_mismatch(monkeypatch, client, db_session):
    async def fake_validate_social_token(provider, access_token):
        return {"email": "mismatch@example.com"}

    monkeypatch.setattr("j_user_auth_svc.routers.login.validate_social_token", fake_validate_social_token)
    session = db_session
    user = User(email="mismatch@example.com", hashed_password="not_twitter_social")
    session.add(user)
    session.commit()

    response = client.post("/login/twitter", json={"access_token": "dummy_token"})
    assert response.status_code == 401
    assert "Provider mismatch" in response.json().get("detail", "")
