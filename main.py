from typing import List
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import jwt

from database import engine, Base, get_db
import models
import schemas
import security

# Generate tables automatically in MySQL
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="JWT Authentication & RBAC API",
    description="Task 03 - JWT-based Authentication and Role-Based Authorization",
    version="3.0.0"
)

security_bearer = HTTPBearer()


# --- Authentication & Authorization Dependencies ---
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_bearer),
    db: Session = Depends(get_db)
) -> models.User:
    token = credentials.credentials
    try:
        payload = security.decode_access_token(token)
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload invalid: missing user identifier."
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please log in again."
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials."
        )

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User associated with token no longer exists."
        )
    return user


def require_role(required_role: models.UserRole):
    """Factory dependency for role-based permission verification."""
    def role_checker(current_user: models.User = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: requires '{required_role.value}' privileges."
            )
        return current_user
    return role_checker


# --- Public Auth Endpoints ---
@app.post("/auth/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: schemas.UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists."
        )

    hashed_pwd = security.hash_password(payload.password)
    user = models.User(
        name=payload.name,
        email=payload.email,
        hashed_password=hashed_pwd,
        age=payload.age,
        role=payload.role
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=schemas.Token)
def login(payload: schemas.UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user or not security.verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    token = security.create_access_token(data={"sub": str(user.id), "role": user.role.value})
    return {"access_token": token, "token_type": "bearer"}


# --- Protected Endpoints ---
@app.get("/users/me", response_model=schemas.UserResponse)
def get_current_user_profile(current_user: models.User = Depends(get_current_user)):
    """Accessible by any valid authenticated user (user or admin)."""
    return current_user


@app.get("/admin/users", response_model=List[schemas.UserResponse])
def get_all_users_admin(
    admin: models.User = Depends(require_role(models.UserRole.ADMIN)),
    db: Session = Depends(get_db)
):
    """Restricted: Accessible ONLY by users with the 'admin' role."""
    return db.query(models.User).all()