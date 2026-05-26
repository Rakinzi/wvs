from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app import db
from app.models import VerifiedTarget
from app.routes import targets as targets_routes
from app.settings import settings


class FakeResponse:
    def __init__(self, *, body: str = "", status_code: int = 200, headers: dict | None = None):
        self._body = body.encode("utf-8")
        self.status_code = status_code
        self.headers = headers or {}
        self.encoding = "utf-8"

    @property
    def is_redirect(self) -> bool:
        return self.status_code in {301, 302, 303, 307, 308}

    @property
    def is_permanent_redirect(self) -> bool:
        return self.status_code in {301, 308}

    def iter_content(self, chunk_size: int = 8192):
        for index in range(0, len(self._body), chunk_size):
            yield self._body[index:index + chunk_size]

    def close(self):
        return None


def test_create_target_accepts_public_https_target(auth_client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_scan_targets", False)

    response = auth_client.post(
        "/targets",
        json={"target_url": "https://example.com", "verification_method": "meta_tag"},
        headers=auth_headers,
    )

    assert response.status_code == 201
    data = response.get_json()
    assert data["status"] == "success"
    assert data["target"]["normalized_domain"] == "example.com"
    assert data["target"]["verification_status"] == "pending"
    assert data["verification_token"]
    assert "tag" in data["instructions"]


def test_create_target_rejects_localhost(auth_client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_scan_targets", False)

    response = auth_client.post(
        "/targets",
        json={"target_url": "https://localhost", "verification_method": "meta_tag"},
        headers=auth_headers,
    )

    assert response.status_code == 400
    assert "Local network targets are not allowed" in response.get_json()["error"]


def test_create_target_rejects_private_ip(auth_client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_scan_targets", False)

    response = auth_client.post(
        "/targets",
        json={"target_url": "https://192.168.1.10", "verification_method": "meta_tag"},
        headers=auth_headers,
    )

    assert response.status_code == 400
    assert "Private or reserved network targets are not allowed" in response.get_json()["error"]


def test_create_target_rejects_embedded_credentials(auth_client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_scan_targets", False)

    response = auth_client.post(
        "/targets",
        json={"target_url": "https://user:pass@example.com", "verification_method": "meta_tag"},
        headers=auth_headers,
    )

    assert response.status_code == 400
    assert "embedded credentials" in response.get_json()["error"]


def test_verify_target_rejects_redirect_to_private_ip(auth_client, auth_headers, app, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_scan_targets", False)

    create_response = auth_client.post(
        "/targets",
        json={"target_url": "https://example.com", "verification_method": "meta_tag"},
        headers=auth_headers,
    )
    payload = create_response.get_json()
    target_id = payload["target"]["id"]
    token = payload["verification_token"]

    def fake_get(url, **kwargs):
        return FakeResponse(status_code=302, headers={"Location": "http://169.254.169.254/latest/meta-data"})

    monkeypatch.setattr(targets_routes.requests, "get", fake_get)

    verify_response = auth_client.post(
        f"/targets/{target_id}/verify",
        json={"token": token},
        headers=auth_headers,
    )

    assert verify_response.status_code == 400
    assert "not allowed" in verify_response.get_json()["error"]


def test_verify_target_succeeds_with_meta_tag(auth_client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_scan_targets", False)

    create_response = auth_client.post(
        "/targets",
        json={"target_url": "https://example.com", "verification_method": "meta_tag"},
        headers=auth_headers,
    )
    payload = create_response.get_json()
    target_id = payload["target"]["id"]
    token = payload["verification_token"]

    html = f"""
    <html>
      <head><meta name="wvs-site-verification" content="{token}" /></head>
      <body>ok</body>
    </html>
    """
    monkeypatch.setattr(targets_routes.requests, "get", lambda url, **kwargs: FakeResponse(body=html))

    verify_response = auth_client.post(
        f"/targets/{target_id}/verify",
        json={"token": token},
        headers=auth_headers,
    )

    assert verify_response.status_code == 200
    data = verify_response.get_json()
    assert data["target"]["verification_status"] == "verified"
    assert data["target"]["verified_at"] is not None


def test_verify_target_succeeds_with_well_known_file(auth_client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_scan_targets", False)

    create_response = auth_client.post(
        "/targets",
        json={"target_url": "https://example.com", "verification_method": "well_known_file"},
        headers=auth_headers,
    )
    payload = create_response.get_json()
    target_id = payload["target"]["id"]
    token = payload["verification_token"]

    monkeypatch.setattr(targets_routes.requests, "get", lambda url, **kwargs: FakeResponse(body=token))

    verify_response = auth_client.post(
        f"/targets/{target_id}/verify",
        json={"token": token},
        headers=auth_headers,
    )

    assert verify_response.status_code == 200
    assert verify_response.get_json()["target"]["verification_status"] == "verified"


def test_verify_target_rejects_invalid_token(auth_client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_scan_targets", False)

    create_response = auth_client.post(
        "/targets",
        json={"target_url": "https://example.com", "verification_method": "meta_tag"},
        headers=auth_headers,
    )
    payload = create_response.get_json()
    target_id = payload["target"]["id"]

    verify_response = auth_client.post(
        f"/targets/{target_id}/verify",
        json={"token": "wrong-token"},
        headers=auth_headers,
    )

    assert verify_response.status_code == 400
    assert "did not match" in verify_response.get_json()["error"]


def test_verify_target_rejects_expired_token(auth_client, auth_headers, app, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_scan_targets", False)

    create_response = auth_client.post(
        "/targets",
        json={"target_url": "https://example.com", "verification_method": "meta_tag"},
        headers=auth_headers,
    )
    payload = create_response.get_json()
    target_id = payload["target"]["id"]
    token = payload["verification_token"]

    with app.app_context():
        target = VerifiedTarget.query.filter_by(public_id=target_id).first()
        target.token_expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
        db.session.commit()

    verify_response = auth_client.post(
        f"/targets/{target_id}/verify",
        json={"token": token},
        headers=auth_headers,
    )

    assert verify_response.status_code == 400
    assert "expired" in verify_response.get_json()["error"]


def test_get_target_does_not_expose_raw_verification_token(auth_client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_scan_targets", False)

    create_response = auth_client.post(
        "/targets",
        json={"target_url": "https://example.com", "verification_method": "meta_tag"},
        headers=auth_headers,
    )
    payload = create_response.get_json()
    target_id = payload["target"]["id"]

    detail_response = auth_client.get(f"/targets/{target_id}")

    assert detail_response.status_code == 200
    data = detail_response.get_json()
    assert "verification_token" not in data["target"]
