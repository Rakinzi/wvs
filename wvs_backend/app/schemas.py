from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class AuthRegisterPayload(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)
    email: EmailStr

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            raise ValueError("Username may only contain letters, numbers, dots, dashes, and underscores")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 10:
            raise ValueError("Password must be at least 10 characters long")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must include a lowercase letter")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must include an uppercase letter")
        if not re.search(r"[0-9]", value):
            raise ValueError("Password must include a number")
        return value


class AuthLoginPayload(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class ForgotPasswordPayload(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr


class ResetPasswordPayload(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    token: str = Field(min_length=16, max_length=512)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return AuthRegisterPayload.validate_password(value)


class ScanRequestPayload(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    url: str = Field(min_length=8, max_length=2048)


class AddMaliciousPayload(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    url: str = Field(min_length=8, max_length=2048)
    reason: str = Field(default="", max_length=255)


class BlockedLogPayload(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    url: str = Field(min_length=8, max_length=2048)
    ip_address: str | None = Field(default=None, max_length=50)
    user_agent: str | None = Field(default=None, max_length=500)
    reason: str | None = Field(default=None, max_length=255)
