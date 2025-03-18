from sqlalchemy import Column, Integer, String
from j_user_auth_svc.models.base import Base


class User(Base):
    """
    SQLAlchemy model representing a user in the authentication system.
    Attributes:
        id (int): Unique identifier for the user.
        email (str): User's unique email address.
        hashed_password (str): User's hashed password.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
