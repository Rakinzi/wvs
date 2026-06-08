from __future__ import annotations

import functools
from typing import Annotated

import jwt as pyjwt
from fastapi import Cookie, Depends, Header, HTTPException, status

from app import db
from app.models import User
from app.settings import settings


def _decode_token(token: str | None) -> str | None:
    if not token:
        return None
    try:
        payload = pyjwt.decode(
            token,
            settings.effective_jwt_secret_key,
            algorithms=["HS256"],
        )
        return payload.get("sub")
    except pyjwt.PyJWTError:
        return None


def _identity_from_request(
    access_token_cookie: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None),
) -> str | None:
    if access_token_cookie:
        return _decode_token(access_token_cookie)
    if authorization and authorization.lower().startswith("bearer "):
        return _decode_token(authorization[7:].strip())
    return None


def _user_from_identity(identity: str | None) -> User | None:
    if identity is None:
        return None
    try:
        user_id = int(identity)
    except (TypeError, ValueError):
        return User.query.filter_by(username=identity).first()
    return db.session.get(User, user_id)


def get_current_user() -> User | None:
    """Non-raising helper for internal use (e.g. tasks, legacy callers)."""
    return None  # stateless outside request scope; use Depends instead


# ── FastAPI dependencies ────────────────────────────────────────────────────

def _optional_user(
    access_token_cookie: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None),
) -> User | None:
    identity = _identity_from_request(access_token_cookie, authorization)
    return _user_from_identity(identity)


def current_user(user: Annotated[User | None, Depends(_optional_user)]) -> User:
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


def current_user_optional(user: Annotated[User | None, Depends(_optional_user)]) -> User | None:
    return user


def require_admin(user: Annotated[User, Depends(current_user)]) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def require_role(*roles: str):
    """Return a FastAPI dependency that checks the user's role."""
    def _check(user: Annotated[User, Depends(current_user)]) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user
    return _check


# Keep as a request-scoped helper for routes that received `user` as a param
def get_user_from_cookie(
    access_token_cookie: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None),
) -> User | None:
    identity = _identity_from_request(access_token_cookie, authorization)
    return _user_from_identity(identity)
