from __future__ import annotations


def test_cookie_authenticated_write_requires_csrf_token(auth_client):
    response = auth_client.post(
        "/targets",
        json={"target_url": "https://example.com", "verification_method": "meta_tag"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "CSRF token missing or invalid"


def test_login_response_exposes_rate_limit_headers(client):
    response = client.post(
        "/login",
        json={"identifier": "missing-user", "password": "WrongPassword123"},
    )

    assert response.status_code == 401
    assert response.headers["X-RateLimit-Limit"] == "10"
    assert int(response.headers["X-RateLimit-Remaining"]) < 10
