import os
import hashlib
import secrets
import re

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from backend.database import get_connection

router = APIRouter(prefix="/auth", tags=["Authentication"])
bearer_scheme = HTTPBearer(auto_error=False)

SESSION_HOURS = 24
PBKDF2_ITERATIONS = 310_000


def utc_now():
    return datetime.now(timezone.utc)


def hash_password(password: str, salt: bytes) -> str:
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return derived.hex()


def validate_email(email: str) -> str:
    email = email.strip().lower()

    if len(email) > 254 or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+", email
    ):
        raise HTTPException(
            status_code=400,
            detail="Please enter a valid email address.",
        )

    return email


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(max_length=254)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=128)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Please log in.")

    token_hash = hashlib.sha256(
        credentials.credentials.encode("utf-8")
    ).hexdigest()

    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT u.user_id, u.name, u.email, u.role,
                   s.session_id, s.expires_at
            FROM auth_sessions s
            JOIN users u ON u.user_id = s.user_id
            WHERE s.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid session. Please log in again.",
            )

        expires_at = datetime.fromisoformat(row["expires_at"])

        if expires_at <= utc_now():
            connection.execute(
                "DELETE FROM auth_sessions WHERE session_id = ?",
                (row["session_id"],),
            )
            connection.commit()
            raise HTTPException(
                status_code=401,
                detail="Session expired. Please log in again.",
            )

        return {
            "user_id": row["user_id"],
            "name": row["name"],
            "email": row["email"],
            "role": row["role"],
        }

    finally:
        connection.close()


def require_admin(user=Depends(get_current_user)):
    if user["role"] != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="Admin access required.",
        )
    return user


def require_user(user=Depends(get_current_user)):
    if user["role"] != "USER":
        raise HTTPException(
            status_code=403,
            detail="User access required.",
        )
    return user

@router.post("/register", status_code=201)
def register(request: RegisterRequest):
    name = request.name.strip()
    email = validate_email(request.email)

    if len(name) < 2:
        raise HTTPException(
            status_code=400,
            detail="Name must contain at least 2 characters.",
        )

    salt = secrets.token_bytes(16)
    password_hash = hash_password(request.password, salt)
    created_at = utc_now().isoformat()

    connection = get_connection()

    try:
        # Role is deliberately not accepted from the registration form.
        connection.execute(
            """
            INSERT INTO users
                (name, email, password_hash, password_salt, role, created_at)
            VALUES (?, ?, ?, ?, 'USER', ?)
            """,
            (
                name,
                email,
                password_hash,
                salt.hex(),
                created_at,
            ),
        )
        connection.commit()

        return {
            "message": "Registration successful. Please log in.",
            "email": email,
        }

    except Exception as error:
        connection.rollback()

        if isinstance(error, HTTPException):
            raise

        if "UNIQUE constraint failed: users.email" in str(error):
            raise HTTPException(
                status_code=409,
                detail="An account with this email already exists.",
            )

        raise HTTPException(
            status_code=500,
            detail="Registration failed.",
        )

    finally:
        connection.close()


@router.post("/login")
def login(request: LoginRequest):
    email = validate_email(request.email)
    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT user_id, name, email, password_hash,
                   password_salt, role
            FROM users
            WHERE email = ? COLLATE NOCASE
            """,
            (email,),
        ).fetchone()

        if user is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password.",
            )

        try:
            salt = bytes.fromhex(user["password_salt"])
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=500,
                detail="Account credentials need administrator attention.",
            )

        submitted_hash = hash_password(request.password, salt)

        if not secrets.compare_digest(
            submitted_hash, user["password_hash"]
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password.",
            )

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = utc_now()
        expires_at = now + timedelta(hours=SESSION_HOURS)

        connection.execute(
            """
            INSERT INTO auth_sessions
                (user_id, token_hash, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                user["user_id"],
                token_hash,
                expires_at.isoformat(),
                now.isoformat(),
            ),
        )
        connection.commit()

        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_at": expires_at.isoformat(),
            "user": {
                "user_id": user["user_id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
            },
        }

    finally:
        connection.close()


@router.get("/me")
def get_me(user=Depends(get_current_user)):
    return {"user": user}


@router.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    user=Depends(get_current_user),
):
    token_hash = hashlib.sha256(
        credentials.credentials.encode("utf-8")
    ).hexdigest()

    connection = get_connection()

    try:
        connection.execute(
            "DELETE FROM auth_sessions WHERE token_hash = ?",
            (token_hash,),
        )
        connection.commit()
        return {"message": "Logged out successfully."}
    finally:
        connection.close()

def ensure_admin_account():
    admin_email = os.getenv(
        "PHISHGUARD_ADMIN_EMAIL",
        "admin@phishguard.com",
    ).strip().lower()

    admin_password = os.getenv(
        "PHISHGUARD_ADMIN_PASSWORD",
        "admin123",
    )

    if len(admin_password) < 8:
        raise RuntimeError(
            "PHISHGUARD_ADMIN_PASSWORD must be at least 8 characters."
        )

    salt = secrets.token_bytes(16)
    password_hash = hash_password(admin_password, salt)

    connection = get_connection()

    try:
        existing = connection.execute(
            "SELECT user_id FROM users WHERE email = ? COLLATE NOCASE",
            (admin_email,),
        ).fetchone()

        if existing:
            connection.execute(
                """
                UPDATE users
                SET name = 'PhishGuard Admin',
                    password_hash = ?,
                    password_salt = ?,
                    role = 'ADMIN'
                WHERE user_id = ?
                """,
                (password_hash, salt.hex(), existing["user_id"]),
            )
        else:
            connection.execute(
                """
                INSERT INTO users
                    (name, email, password_hash, password_salt, role, created_at)
                VALUES (?, ?, ?, ?, 'ADMIN', ?)
                """,
                (
                    "PhishGuard Admin",
                    admin_email,
                    password_hash,
                    salt.hex(),
                    utc_now().isoformat(),
                ),
            )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
