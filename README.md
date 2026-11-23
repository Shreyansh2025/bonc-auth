# bonc-auth

A small reusable Python package for Flask and FastAPI services that need to verify a user's BONC bearer token through the company-owned .NET verification endpoint.

**This package does not create JWTs, implement login/logout, or connect to SQL Server.** BONC's .NET backend remains responsible for validating the token and checking the user's active session.

## Current status

- Initial package version: `0.1.0`
- Flask Blueprint integration: included
- FastAPI dependency integration: included
- Real BONC endpoint contract: not yet confirmed; configure it before connecting a real environment

## Install from GitHub

Flask only:

```bash
pip install "bonc-auth[flask] @ git+https://github.com/Shreyansh2025/bonc-auth.git@main"
```

FastAPI only:

```bash
pip install "bonc-auth[fastapi] @ git+https://github.com/Shreyansh2025/bonc-auth.git@main"
```

Both integrations:

```bash
pip install "bonc-auth[all] @ git+https://github.com/Shreyansh2025/bonc-auth.git@main"
```

After creating a release tag, use that tag (for example `@v0.1.0`) instead of `@main` so projects remain pinned to a known version.

## Verification endpoint contract

The package forwards the incoming user token to the configured verification endpoint in the `Authorization` header. The default method is GET, matching the example discussed with the team. POST is also configurable.

Example request:

```http
GET /api/auth/verify-admin
Authorization: Bearer <user-access-token>
Accept: application/json
```

The example endpoint from the discussion returns an authenticated user on HTTP 200:

```json
{
  "adminId": "stable-user-id",
  "role": "Admin",
  "sessionId": "active-session-id"
}
```

Expected status handling:

- `200`: token and session accepted; response must contain the configured user ID field.
- `401`: invalid, expired, or revoked token/session.
- `403`: verification endpoint denied access.
- Any other status, timeout, malformed JSON, or connection error: fail closed with HTTP 503 from the protected Python API.

The response field names are configurable. If BONC instead returns `user_id`, `roles`, `permissions`, or an `active` field, configure `BoncAuth` accordingly. Ask the company to confirm the endpoint URL, method, response schema and service-to-service protection before production use.

If the verification endpoint requires a separate service credential, pass it using `service_headers`. Do not put the caller's user token there; the package uses the `Authorization` header for the user's token. Keep service credentials on the backend only (environment variables or a secret manager), never in frontend code.

## Flask usage

Attach the guard to an admin Blueprint once:

```python
import os
from flask import Blueprint, g, jsonify
from bonc_auth import BoncAuth
from bonc_auth.flask import FlaskBoncAuth

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

bonc_client = BoncAuth(
    verify_url=os.environ["BONC_AUTH_VERIFY_URL"],
    method=os.getenv("BONC_AUTH_VERIFY_METHOD", "GET"),
    timeout=3.0,
    # Defaults match the example .NET response: adminId, role, sessionId.
)
admin_auth = FlaskBoncAuth(bonc_client)
admin_auth.protect_blueprint(admin_bp, required_role="Admin")

@admin_bp.get("/me")
def me():
    return jsonify({"admin_id": g.bonc_user.user_id})
```

For one route requiring an additional permission:

```python
@admin_bp.post("/moderation/approve")
@admin_auth.require_permission("moderation.write")
def approve_content():
    return {"status": "ok"}
```

Register the Blueprint after attaching the guard. OPTIONS preflight requests are allowed by default; CORS must still be configured correctly in the application.

## FastAPI usage

```python
import os
from fastapi import APIRouter, Depends
from bonc_auth import BoncAuth
from bonc_auth.fastapi import FastAPIBoncAuth

router = APIRouter()
bonc_client = BoncAuth(
    verify_url=os.environ["BONC_AUTH_VERIFY_URL"],
    method=os.getenv("BONC_AUTH_VERIFY_METHOD", "GET"),
    timeout=3.0,
)
bonc_auth = FastAPIBoncAuth(bonc_client)

@router.get("/admin/me")
async def me(user=Depends(bonc_auth.require_role("Admin"))):
    return {"admin_id": user.user_id}

@router.get("/admin/audit")
async def read_audit(user=Depends(bonc_auth.require_permission("moderation.read"))):
    return {"requested_by": user.user_id}
```

## Security behavior

- No local JWT decoding: the trusted .NET endpoint must verify signature, issuer, audience, expiry and active session.
- HTTPS is required by default except for localhost development.
- Redirects are not followed when sending the user's token to the verifier.
- Invalid tokens return 401; insufficient permissions return 403; unavailable or malformed verifier responses return 503.
- The package fails closed. It never grants access when the verifier is unreachable.
- User tokens and secrets are not written to logs.
- Every protected application endpoint must still enforce its required role or permission.

## Develop, test and build

```bash
python -m venv .venv
# Activate the virtual environment, then:
python -m pip install -e ".[dev]"
pytest
python -m build
```

The build creates a wheel and source distribution under `dist/`.

## Python package hosting

GitHub Packages does not currently list a Python/PyPI-compatible registry. Keep the source code in this GitHub repository and install it from a tag, or publish the Python distribution to PyPI (or an approved private Python package index). PyPI Trusted Publishing can publish from GitHub Actions without a long-lived PyPI API token, after a trusted publisher is configured and the team approves the release process.

## License and internal use

This package is intended for the BONC projects agreed by the maintainers. Confirm the repository visibility and licensing with the company before distributing it outside those projects.
