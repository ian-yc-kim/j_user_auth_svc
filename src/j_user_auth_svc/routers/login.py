import logging
import secrets

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
