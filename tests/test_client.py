import httpx
import pytest

from bonc_auth import BoncAuth, AuthServiceUnavailable, Forbidden, InvalidToken
from bonc_auth.client import extract_bearer_token


def test_extract_bearer_token():
    assert extract_bearer_token("Bearer abc123") == "abc123"


@pytest.mark.parametrize("header", [None, "", "Basic xyz", "Bearer", "Bearer  "])
def test_rejects_invalid_header(header):
    with pytest.raises(InvalidToken):
        extract_bearer_token(header)


def test_verify_sends_bearer_and_returns_admin(monkeypatch):
    def fake_request(method, url, **kwargs):
        assert method == "GET"
        assert kwargs["headers"]["Authorization"] == "Bearer token123"
        return httpx.Response(200, json={"adminId": "admin-1", "role": "Admin", "sessionId": "s1"})

    monkeypatch.setattr("bonc_auth.client.httpx.request", fake_request)
    auth = BoncAuth("https://auth.example.test/api/auth/verify-admin")
    assert auth.verify("token123")["adminId"] == "admin-1"


def test_401_means_invalid_token(monkeypatch):
    monkeypatch.setattr("bonc_auth.client.httpx.request", lambda *a, **k: httpx.Response(401))
    with pytest.raises(InvalidToken):
        BoncAuth("https://auth.example.test/verify").verify("bad")


def test_403_means_not_admin(monkeypatch):
    monkeypatch.setattr("bonc_auth.client.httpx.request", lambda *a, **k: httpx.Response(403))
    with pytest.raises(Forbidden):
        BoncAuth("https://auth.example.test/verify").verify("user")


def test_bad_verifier_response_fails_closed(monkeypatch):
    monkeypatch.setattr("bonc_auth.client.httpx.request", lambda *a, **k: httpx.Response(200, json={"ok": True}))
    with pytest.raises(AuthServiceUnavailable):
        BoncAuth("https://auth.example.test/verify").verify("token")
