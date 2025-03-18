import os
import asyncio
import pytest
import httpx

from fastapi import HTTPException, status
from j_user_auth_svc.routers.login import validate_social_token


class FakeResponse:
    def __init__(self, status_code, json_data, text=None):
        self.status_code = status_code
        self._json = json_data
        self.text = text or str(json_data)

    def json(self):
        return self._json


class FakeAsyncClient:
    def __init__(self, response_get=None, response_post=None):
        self.response_get = response_get
        self.response_post = response_post

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        pass

    async def get(self, url, **kwargs):
        return self.response_get

    async def post(self, url, **kwargs):
        return self.response_post


@pytest.mark.asyncio
async def test_validate_google_token_valid(monkeypatch):
    # Simulate a valid Google token response
    fake_json = {"email": "user@example.com", "aud": "dummy"}
    fake_response = FakeResponse(200, fake_json)

    async def fake_get(*args, **kwargs):
        return fake_response

    # Patch the httpx.AsyncClient to use our FakeAsyncClient for GET
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: FakeAsyncClient(response_get=fake_response))

    result = await validate_social_token("google", "valid_token")
    assert result == fake_json


@pytest.mark.asyncio
async def test_validate_google_token_invalid(monkeypatch):
    # Simulate an invalid Google token response (missing email)
    fake_json = {"aud": "dummy"}
    fake_response = FakeResponse(200, fake_json, text='Missing email')

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: FakeAsyncClient(response_get=fake_response))

    with pytest.raises(HTTPException) as exc_info:
        await validate_social_token("google", "invalid_token")
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_validate_apple_token_valid(monkeypatch):
    # Set environment variables for Apple credentials
    monkeypatch.setenv("APPLE_CLIENT_ID", "apple_id")
    monkeypatch.setenv("APPLE_CLIENT_SECRET", "apple_secret")

    fake_json = {"user": "apple_user"}
    fake_response = FakeResponse(200, fake_json)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: FakeAsyncClient(response_post=fake_response))

    result = await validate_social_token("apple", "valid_apple_token")
    assert result == fake_json


@pytest.mark.asyncio
async def test_validate_twitter_token_valid(monkeypatch):
    # Set environment variables for Twitter credentials
    monkeypatch.setenv("TWITTER_CLIENT_ID", "twitter_id")
    monkeypatch.setenv("TWITTER_CLIENT_SECRET", "twitter_secret")

    fake_json = {"user": "twitter_user"}
    fake_response = FakeResponse(200, fake_json)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: FakeAsyncClient(response_post=fake_response))

    result = await validate_social_token("twitter", "valid_twitter_token")
    assert result == fake_json


@pytest.mark.asyncio
async def test_validate_token_network_error(monkeypatch):
    # Simulate a network error by having AsyncClient raise a RequestError
    from httpx import RequestError

    class FailingAsyncClient:
        async def __aenter__(self):
            raise RequestError("Network down")
        async def __aexit__(self, exc_type, exc, tb):
            pass

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: FailingAsyncClient())

    with pytest.raises(HTTPException) as exc_info:
        await validate_social_token("google", "any_token")
    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


@pytest.mark.asyncio
async def test_validate_token_unsupported_provider():
    with pytest.raises(HTTPException) as exc_info:
        await validate_social_token("unsupported", "token")
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
