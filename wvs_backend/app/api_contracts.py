from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    error: str | None = None
    message: str | None = None
    status: str | None = None
    errors: list[dict[str, Any]] | None = None


class LoginResponse(BaseModel):
    username: str
    user_id: int
    is_admin: bool
    expires_in: int


class ProfileResponse(BaseModel):
    username: str
    email: str
    created_on: str
    email_verified: bool
    is_admin: bool


class ScanAcceptedResponse(BaseModel):
    status: Literal["accepted"]
    job_id: str
    task_id: str
    url: str
    scan_profile: str
    message: str
    timestamp: str


class ScanJobProgressResponse(BaseModel):
    model_config = ConfigDict(extra="allow")


class ScanJobResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    url: str
    scan_type: str
    status: str
    task_id: str | None = None
    findings: dict[str, Any] | None = None
    error_message: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    user_id: int
    result_id: str | None = None
    scan_id: str | None = None
    has_vulnerabilities: bool | None = None
    progress: ScanJobProgressResponse | None = None


class ScanJobEnvelope(BaseModel):
    status: Literal["success"]
    job: ScanJobResponse


class ScanJobsEnvelope(BaseModel):
    status: Literal["success"]
    jobs: list[ScanJobResponse] = Field(default_factory=list)
