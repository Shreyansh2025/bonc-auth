import asyncio

import pytest
pytest.importorskip("fastapi")

from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from bonc_auth.fastapi import FastAPIBoncAuth
from bonc_auth.models import VerifiedUser


class FakeAuth:
    async def authenticate_header_async(self, authorization):
        if authorization != "Bearer good-token":
            from bonc_auth.exceptions import InvalidToken
            raise InvalidToken("invalid")
        return VerifiedUser(
            user_id="admin-1",
            roles=frozenset({"Admin"}),
            permissions=frozenset({"moderation.read"}),
        )


def test_fastapi_permission_dependency_allows_verified_user():
    auth = FastAPIBoncAuth(FakeAuth())
    app = FastAPI()

    @app.get("/admin/audit")
    async def read_audit(user=Depends(auth.require_permission("moderation.read"))):
        return {"user_id": user.user_id}

    response = TestClient(app).get(
        "/admin/audit", headers={"Authorization": "Bearer good-token"}
    )
    assert response.status_code == 200
    assert response.json() == {"user_id": "admin-1"}


def test_fastapi_dependency_rejects_missing_token():
    auth = FastAPIBoncAuth(FakeAuth())
    app = FastAPI()

    @app.get("/admin/audit")
    async def read_audit(user=Depends(auth.require_user)):
        return {"user_id": user.user_id}

    response = TestClient(app).get("/admin/audit")
    assert response.status_code == 401
