import logging
import secrets
import os

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from j_user_auth_svc.models.base import get_db
from j_user_auth_svc.models.user import User

router = APIRouter()

# Create a CryptContext for password hashing and verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginRequest(BaseModel):
    """
    Pydantic model for login request containing email and password.
    """
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    """
    Pydantic model for login response containing a session token.
    """
    session_token: str


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against its hashed version using passlib.
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logging.error(e, exc_info=True)
        return False


def create_session_token(user: User) -> str:
    """
    Generate a secure session token using Python's secrets module.
    """
    try:
        return secrets.token_urlsafe(32)
    except Exception as e:
        logging.error(e, exc_info=True)
        raise


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    """
    Login endpoint to authenticate a user with email and password.

    On successful authentication, returns a secure session token in the response.
    Raises HTTPException with status 401 if credentials are invalid or if an error occurs.
    """
    try:
        stmt = select(User).filter(User.email == request.email)
        result = db.execute(stmt)
        user = result.scalars().first()

        if not user or not verify_password(request.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        token = create_session_token(user)
        return LoginResponse(session_token=token)
    except HTTPException:
        raise
    except Exception as e:
        logging.error(e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


async def validate_social_token(provider: str, access_token: str) -> dict:
    """
    Validate a social login token with an external OAuth2 provider.

    Providers supported:
      - google: Validates token via a GET request to Google OAuth2 endpoint.
      - apple: Validates token via a POST request to Apple token endpoint.
      - twitter: Validates token via a POST request to Twitter OAuth2 endpoint.

    Parameters:
      provider (str): Identifier of the external provider ('google', 'apple', 'twitter').
      access_token (str): Token provided by the client.

    Returns:
      dict: JSON response from the provider if the token is valid.

    Raises:
      HTTPException: 400 for unsupported provider, 401 for invalid token, and 500 for internal errors.
    
    Note: Rate limiting and additional validations may be applied in the future.
    """
    try:
        if not access_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token is missing")

        if provider == "google":
            url = f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={access_token}"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url)

        elif provider == "apple":
            url = "https://appleid.apple.com/auth/2.0/token"
            client_id = os.getenv("APPLE_CLIENT_ID")
            client_secret = os.getenv("APPLE_CLIENT_SECRET")
            if not client_id or not client_secret:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Apple credentials are not configured")
            payload = {
                "client_id": client_id,
                "client_secret": client_secret,
                "token": access_token
            }
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(url, data=payload)

        elif provider == "twitter":
            url = "https://api.twitter.com/2/oauth2/token"
            client_id = os.getenv("TWITTER_CLIENT_ID")
            client_secret = os.getenv("TWITTER_CLIENT_SECRET")
            if not client_id or not client_secret:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Twitter credentials are not configured")
            headers = {
                "Authorization": f"Bearer {access_token}"
            }
            payload = {
                "client_id": client_id,
                "client_secret": client_secret
            }
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(url, headers=headers, data=payload)

        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported provider")

        if response.status_code != 200:
            logging.error(f"{provider} token validation failed: HTTP {response.status_code} - {response.text}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

        data = response.json()

        if provider == "google":
            # Ensure the response contains an email attribute
            if "email" not in data:
                logging.error("Google token validation failed: 'email' not found in response")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        # Future enhancements: Additional checks for apple and twitter responses

        return data

    except httpx.RequestError as e:
        logging.error(f"Network error during {provider} token validation: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Network error")
    except HTTPException:
        raise
    except Exception as e:
        logging.error(e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


class GoogleLoginRequest(BaseModel):
    """
    Pydantic model for Google social login request containing the access token.
    """
    access_token: str


@router.post("/login/google", response_model=LoginResponse)
async def google_login(request: GoogleLoginRequest, db: Session = Depends(get_db)):
    """
    Google social login endpoint.

    Accepts a JSON payload with an 'access_token', validates the token through Google's OAuth endpoint,
    extracts the user's email, and verifies the user in the database.

    Returns:
      - HTTP 200 with a session token if successful.
      - HTTP 401 if token is invalid, provider mismatches, or user is not found.
      - HTTP 500 for unexpected errors.
    
    Note: New user creation can be optionally implemented if user does not exist.
    """
    try:
        # Validate the social token with provider 'google'
        token_data = await validate_social_token("google", request.access_token)
        email = token_data.get("email")
        if not email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email not found in token response")

        # Query the database for a user with the extracted email
        stmt = select(User).filter(User.email == email)
        result = db.execute(stmt)
        user = result.scalars().first()

        if user:
            # Check if the user was registered via Google social login (using sentinel value 'google_social')
            if user.hashed_password == "google_social":
                session_token = create_session_token(user)
                return LoginResponse(session_token=session_token)
            else:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Provider mismatch: user not registered with Google")
        else:
            # User not found; new user creation may be optionally implemented according to business rules
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found. New user creation is not implemented")
    except HTTPException:
        raise
    except Exception as e:
        logging.error(e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
