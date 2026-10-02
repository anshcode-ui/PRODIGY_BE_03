from uuid import UUID
from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from models import UserRole


class UserRegister(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, example="Jane Doe")
    email: EmailStr = Field(..., example="jane.doe@example.com")
    password: str = Field(..., min_length=6, example="Secret123!")
    age: int = Field(..., ge=0, le=130, example=24)
    role: Optional[UserRole] = Field(default=UserRole.USER, example="user")


class UserLogin(BaseModel):
    email: EmailStr = Field(..., example="jane.doe@example.com")
    password: str = Field(..., example="Secret123!")


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: UUID
    name: str
    email: EmailStr
    age: int
    role: UserRole

    class Config:
        from_attributes = True