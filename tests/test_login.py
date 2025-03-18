import pytest
from fastapi import status
from passlib.context import CryptContext

from j_user_auth_svc.models.user import User

# Create a CryptContext to hash passwords for testing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def test_successful_login(client, db_session):
    # Setup: create a user with known credentials using hashed password
    session = db_session
    hashed = pwd_context.hash("secret")
    new_user = User(email="test@example.com", hashed_password=hashed)
    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    response = client.post("/login", json={"email": "test@example.com", "password": "secret"})
    assert response.status_code == 200
    data = response.json()
    # Instead of checking for an exact token value, verify that a non-empty token is returned
    assert "session_token" in data
    assert isinstance(data["session_token"], str)
    assert len(data["session_token"]) > 0


def test_wrong_password(client, db_session):
    session = db_session
    hashed = pwd_context.hash("secret")
    new_user = User(email="fail@example.com", hashed_password=hashed)
    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    response = client.post("/login", json={"email": "fail@example.com", "password": "wrong"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_missing_field(client):
    # Missing password field; Pydantic validation error returns 422
    response = client.post("/login", json={"email": "test@example.com"})
    assert response.status_code == 422


def test_invalid_email_format(client):
    # Invalid email format will be caught by Pydantic
    response = client.post("/login", json={"email": "not-an-email", "password": "secret"})
    assert response.status_code == 422
