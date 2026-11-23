import pytest
pytest.importorskip("fastapi")

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from bonc_auth.fastapi import FastAPIAdminGuard


class FakeAuth:
    async def verify_async(self, token):
        if token != "valid":
            from bonc_auth import InvalidToken
            raise InvalidToken()
        return {"adminId": "admin-1", "role": "Admin", "sessionId": "s1"}


def test_fastapi_dependency_is_protected():
    app = FastAPI()
    guard = FastAPIAdminGuard(FakeAuth())

    @app.get("/admin/me")
    async def me(admin=Depends(guard.require_admin)):
        return {"adminId": admin["adminId"]}

    client = TestClient(app)
    assert client.get("/admin/me").status_code == 401
    response = client.get("/admin/me", headers={"Authorization": "Bearer valid"})
    assert response.status_code == 200
    assert response.json()["adminId"] == "admin-1"
