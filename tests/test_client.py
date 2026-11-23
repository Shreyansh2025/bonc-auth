import httpx
import pytest

from bonc_auth import BoncAuth
from bonc_auth.client import extract_bearer_token
from bonc_auth.exceptions import (
    AuthServiceUnavailable,
    InsufficientPermission,
    InvalidToken,
)


def test_extract_bearer_token():
    assert extract_bearer_token("Bearer abc123") == "abc123"


@pytest.mark.parametrize(
    "header",
    [None, "", "Basic abc123", "Bearer ", "Bearer abc 123", "Bearer  abc123"],
)
def test_rejects_invalid_authorization_header(header):
    with pytest.raises(InvalidToken):
        extract_bearer_token(header)


def test_client_sends_user_token_and_optional_service_header(monkeypatch):
    def fake_request(method, url, **kwargs):
        assert method == "GET"
        assert url == "https://auth.example.test/api/auth/verify-admin"
        assert kwargs["headers"]["Authorization"] == "Bearer incoming-user-token"
        assert kwargs["headers"]["X-Service-Name"] == "moderation-api"
        return httpx.Response(
            200,
            json={"adminId": "admin-1", "role": "Admin", "sessionId": "s-1"},
        )

    monkeypatch.setattr("bonc_auth.client.httpx.request", fake_request)
    client = BoncAuth(
        "https://auth.example.test/api/auth/verify-admin",
        service_headers={"X-Service-Name": "moderation-api"},
    )
    user = client.authenticate_header("Bearer incoming-user-token")
    assert user.user_id == "admin-1"
    assert user.has_role("Admin")


def test_timeout_fails_closed(monkeypatch):
    def fake_request(*args, **kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr("bonc_auth.client.httpx.request", fake_request)
    with pytest.raises(AuthServiceUnavailable):
        BoncAuth("https://auth.example.test/verify").verify_token("token")


def test_unauthorized_response_rejects_token(monkeypatch):
    monkeypatch.setattr(
        "bonc_auth.client.httpx.request",
        lambda *args, **kwargs: httpx.Response(401),
    )
    with pytest.raises(InvalidToken):
        BoncAuth("https://auth.example.test/verify").verify_token("revoked-token")


def test_forbidden_response_is_forbidden(monkeypatch):
    monkeypatch.setattr(
        "bonc_auth.client.httpx.request",
        lambda *args, **kwargs: httpx.Response(403),
    )
    with pytest.raises(InsufficientPermission):
        BoncAuth("https://auth.example.test/verify").verify_token("token")


def test_http_allowed_only_for_localhost_by_default():
    with pytest.raises(ValueError):
        BoncAuth("http://auth.example.test/verify")
    BoncAuth("http://localhost:5000/verify")
