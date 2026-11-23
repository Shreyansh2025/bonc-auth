# bonc-auth

A small Python package for protecting admin APIs in Flask and FastAPI projects using the company's .NET verification endpoint.

**This package does not create JWTs, implement login/logout, or connect to SQL Server.** The .NET backend verifies the token and checks whether its session is still active.

## Expected .NET endpoint behavior

The package forwards the frontend's token to the verification endpoint:

```http
GET /api/auth/verify-admin
Authorization: Bearer <user-access-token>
```

Expected response from the example discussed with the BONC team:

```json
{
  "adminId": "stable-admin-id",
  "role": "Admin",
  "sessionId": "active-session-id"
}
```

- HTTP 200: token and active session accepted; response must contain `adminId`.
- HTTP 401: token invalid, expired, or session logged out/revoked.
- HTTP 403: user is authenticated but does not have admin access.
- Timeout, connection error, unexpected status, or invalid response: the Python API fails closed with HTTP 503.

The company still needs to confirm the real endpoint URL, method, response shape and any service-to-service authentication. The example above is not yet a verified production contract.

## Install

Flask:

```bash
pip install "bonc-auth[flask] @ git+https://github.com/Shreyansh2025/bonc-auth.git@v0.2.0"
```

FastAPI:

```bash
pip install "bonc-auth[fastapi] @ git+https://github.com/Shreyansh2025/bonc-auth.git@v0.2.0"
```

## Flask example

```python
import os
from flask import Blueprint, g, jsonify
from bonc_auth import BoncAuth
from bonc_auth.flask import AdminGuard

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")
auth = BoncAuth(os.environ["BONC_AUTH_VERIFY_URL"])
AdminGuard(auth).protect_blueprint(admin_bp)

@admin_bp.get("/me")
def me():
    return jsonify({"admin_id": g.admin["adminId"]})
```

## FastAPI example

```python
import os
from fastapi import Depends, FastAPI
from bonc_auth import BoncAuth
from bonc_auth.fastapi import FastAPIAdminGuard

app = FastAPI()
auth = BoncAuth(os.environ["BONC_AUTH_VERIFY_URL"])
guard = FastAPIAdminGuard(auth)

@app.get("/api/admin/me")
async def me(admin=Depends(guard.require_admin)):
    return {"admin_id": admin["adminId"]}
```

## Build and test

```bash
python -m pip install -e ".[dev]"
pytest
python -m build
```

The build creates a wheel and source archive in `dist/`.

## Use in other projects

The GitHub repository itself can be used as the package source. Install from a version tag as shown above. GitHub Packages does not currently provide a Python package registry; PyPI or a private Python package index is an optional later publishing step.

## Security

- Use HTTPS for the verification endpoint.
- Keep any service-to-service credentials on the backend only.
- Never log or store the user's bearer token unnecessarily.
- Do not allow access when the verification service is unavailable.
- Protect only the admin routes that require authentication; register public routes on a separate Blueprint/router.
