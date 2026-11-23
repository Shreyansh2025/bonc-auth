"""Shared client: forwards a user's bearer token to the BONC .NET verifier."""

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

import httpx


class BoncAuthError(Exception):
    """Base error for BONC authentication."""


class InvalidToken(BoncAuthError):
    """The token is missing, invalid, expired, or its session was revoked."""


class Forbidden(BoncAuthError):
    """The user is authenticated but does not have admin access."""


class AuthServiceUnavailable(BoncAuthError):
    """The BONC verification service could not safely verify the request."""


def extract_bearer_token(authorization: str | None) -> str:
    """Return a valid Bearer token or raise InvalidToken."""
    parts = authorization.split() if authorization else []
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise InvalidToken("A valid Authorization: Bearer header is required.")
    return parts[1]


class BoncAuth:
    """Call the company-owned .NET endpoint to verify an admin token.

    The .NET endpoint must return HTTP 200 only when the JWT and active session
    are valid. Its example response is {"adminId": "...", "role": "Admin",
    "sessionId": "..."}. A 401 means invalid/revoked; a 403 means not admin.
    """

    def __init__(
        self,
        verify_url: str,
        *,
        method: str = "GET",
        timeout: float = 5.0,
        service_headers: Mapping[str, str] | None = None,
    ) -> None:
        parsed = urlparse(verify_url)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise ValueError("verify_url must be an absolute HTTP(S) URL.")
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Use HTTPS for the BONC verification endpoint.")
        if method.upper() not in {"GET", "POST"}:
            raise ValueError("method must be GET or POST.")
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")
        if any(key.lower() == "authorization" for key in (service_headers or {})):
            raise ValueError("Do not set Authorization in service_headers.")

        self.verify_url = verify_url
        self.method = method.upper()
        self.timeout = timeout
        self.service_headers = dict(service_headers or {})

    def _headers(self, token: str) -> dict[str, str]:
        return {
            **self.service_headers,
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }

    @staticmethod
    def _read_response(response: httpx.Response) -> dict[str, Any]:
        if response.status_code == 401:
            raise InvalidToken("Token is invalid, expired, or the session is no longer active.")
        if response.status_code == 403:
            raise Forbidden("Admin access is required.")
        if response.status_code != 200:
            raise AuthServiceUnavailable(
                f"BONC verification returned HTTP {response.status_code}."
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise AuthServiceUnavailable("BONC returned an invalid JSON response.") from exc

        if not isinstance(data, dict) or not data.get("adminId"):
            raise AuthServiceUnavailable(
                "BONC response must be a JSON object containing adminId."
            )
        return data

    def verify(self, token: str) -> dict[str, Any]:
        """Verify a token synchronously (used by Flask)."""
        if not token:
            raise InvalidToken("Bearer token is empty.")
        try:
            response = httpx.request(
                self.method,
                self.verify_url,
                headers=self._headers(token),
                timeout=self.timeout,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise AuthServiceUnavailable("Could not reach BONC authentication service.") from exc
        return self._read_response(response)

    async def verify_async(self, token: str) -> dict[str, Any]:
        """Verify a token asynchronously (used by FastAPI)."""
        if not token:
            raise InvalidToken("Bearer token is empty.")
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
            ) as client:
                response = await client.request(
                    self.method,
                    self.verify_url,
                    headers=self._headers(token),
                )
        except httpx.RequestError as exc:
            raise AuthServiceUnavailable("Could not reach BONC authentication service.") from exc
        return self._read_response(response)
