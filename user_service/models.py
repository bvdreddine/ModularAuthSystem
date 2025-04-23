from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr, validator
from uuid import UUID, uuid4
from datetime import datetime


class UserRole(str, Enum):
    STUDENT = "student"
    TEACHER = "teacher"
    ADMIN = "admin"


class UserBase(BaseModel):
    """Base model for user data."""
    first_name: str
    last_name: str
    email: EmailStr
    role: UserRole
    phone: Optional[str] = None
    department: Optional[str] = None
    active: bool = True


class UserCreate(UserBase):
    """Model for creating a new user."""
    password: str
    
    @validator("password")
    def password_strength(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(char.isdigit() for char in v):
            raise ValueError("Password must contain at least one digit")
        if not any(char.isupper() for char in v):
            raise ValueError("Password must contain at least one uppercase letter")
        return v


class UserUpdate(BaseModel):
    """Model for updating an existing user."""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    phone: Optional[str] = None
    department: Optional[str] = None
    active: Optional[bool] = None


class User(UserBase):
    """Complete user model with ID and timestamps."""
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        orm_mode = True


class UserInDB(User):
    """Internal representation of user in database."""
    keycloak_id: Optional[str] = None


class UserResponse(User):
    """User model for API responses."""
    pass


class UserListResponse(BaseModel):
    """Response model for list of users."""
    users: List[UserResponse]
    total: int
    page: int
    size: int


class KeycloakUser(BaseModel):
    """Model for Keycloak user creation."""
    username: str
    email: EmailStr
    firstName: str
    lastName: str
    enabled: bool = True
    emailVerified: bool = True
    credentials: List[dict] = []
    attributes: dict = {}
    realmRoles: List[str] = []
