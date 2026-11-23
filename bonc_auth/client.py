"""HTTP client for the company-owned BONC token verification endpoint.

This package does not issue tokens or decode unverified JWT claims. BONC's
.NET endpoint is responsible for validating the token and current session.
"""

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

import httpx

from .exceptions import (
    AuthServiceUnavailable,
    InsufficientPermission,
    InvalidToken,
    InvalidVerificationResponse,
)
from .models import VerifiedUser


def extract_bearer_token(authorization: str | None) -> str:
    """Extract one well-formed Bearer token from an Authorization header."""
    if not authorization:
        raise InvalidToken("Missing Authorization: Bearer header.")

    scheme, separator, token = authorization.partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not token
        or token != token.strip()
        or any(character.isspace() for character in token)
    ):
        raise InvalidToken("Malformed Authorization: Bearer header.")

    return token


class BoncAuth:
    """Verify incoming user tokens through the central BONC endpoint.

    The endpoint's successful HTTP response is treated as proof that its
    configured token and session checks passed. Field names are configurable;
    defaults match the example contract discussed with the BONC team:
    ``adminId``, ``role`` and ``sessionId``.

    Args:
        verify_url: Verification URL supplied by the BONC team.
        service_headers: Optional additional server-to-server headers, if the
            endpoint requires them. Never put frontend credentials here.
        timeout: HTTP timeout in seconds.
        method: HTTP method expected by the verification endpoint (GET/POST).
        user_id_field: Response field containing the stable user/admin ID.
        role_field: Response field containing a role string or list.
        roles_field: Optional response field containing additional roles.
        permissions_field: Response field containing permission strings.
        session_id_field: Optional session ID response field.
        active_field: Optional boolean response field. Set to None if the
            endpoint uses HTTP 200 alone to indicate an active session.
        require_https: Require HTTPS except for localhost during development.
    """

    def __init__(
        self,
        verify_url: str,
        *,
        service_headers: Mapping[str, str] | None = None,
        timeout: float = 3.0,
        method: str = "GET",
        user_id_field: str = "adminId",
        role_field: str = "role",
        roles_field: str = "roles",
        permissions_field: str = "permissions",
        session_id_field: str = "sessionId",
        active_field: str | None = "active",
        require_https: bool = True,
    ) -> None:
        if not isinstance(verify_url, str) or not verify_url.strip():
            raise ValueError("verify_url must be a non-empty URL.")
        parsed = urlparse(verify_url.strip())
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("verify_url must be an absolute HTTP(S) URL.")
        if require_https and parsed.scheme != "https" and parsed.hostname not in local_hosts:
            raise ValueError("verify_url must use HTTPS outside localhost.")
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")

        normalized_method = method.upper()
        if normalized_method not in {"GET", "POST"}:
            raise ValueError("method must be GET or POST.")

        headers = dict(service_headers or {})
        if any(key.lower() == "authorization" for key in headers):
            raise ValueError(
                "Do not set Authorization in service_headers; the user's Bearer "
                "token is sent there. Configure any separate service-auth header instead."
            )

        self.verify_url = verify_url.strip()
        self.service_headers = headers
        self.timeout = timeout
        self.method = normalized_method
        self.response_fields = {
            "user_id_field": user_id_field,
            "role_field": role_field,
            "roles_field": roles_field,
            "permissions_field": permissions_field,
            "session_id_field": session_id_field,
            "active_field": active_field,
        }

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Accept": "application/json",
            **self.service_headers,
            "Authorization": f"Bearer {token}",
        }

    def _parse_response(self, response: httpx.Response) -> VerifiedUser:
        if response.status_code == 401:
            raise InvalidToken("BONC rejected the token or the session is inactive.")
        if response.status_code == 403:
            raise InsufficientPermission("BONC denied access to the verification request.")
        if response.status_code != 200:
            raise AuthServiceUnavailable(
                f"BONC verification service returned HTTP {response.status_code}."
            )

        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise InvalidVerificationResponse(
                "BONC verification service did not return valid JSON."
            ) from exc

        return VerifiedUser.from_response(payload, **self.response_fields)

    def verify_token(self, token: str) -> VerifiedUser:
        """Verify a token synchronously (for Flask and synchronous callers)."""
        if not token:
            raise InvalidToken("Empty bearer token.")
        try:
            response = httpx.request(
                self.method,
                self.verify_url,
                headers=self._headers(token),
                timeout=self.timeout,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise AuthServiceUnavailable(
                "Could not reach the BONC verification service."
            ) from exc
        return self._parse_response(response)

    async def verify_token_async(self, token: str) -> VerifiedUser:
        """Verify a token asynchronously (for FastAPI)."""
        if not token:
            raise InvalidToken("Empty bearer token.")
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
            raise AuthServiceUnavailable(
                "Could not reach the BONC verification service."
            ) from exc
        return self._parse_response(response)

    def authenticate_header(self, authorization: str | None) -> VerifiedUser:
        """Extract and verify a bearer token from a request header."""
        return self.verify_token(extract_bearer_token(authorization))

    async def authenticate_header_async(
        self, authorization: str | None
    ) -> VerifiedUser:
        """Asynchronously extract and verify a bearer token from a request header."""
        return await self.verify_token_async(extract_bearer_token(authorization))
