import pytest
pytest.importorskip("flask")

from flask import Blueprint, Flask, g
from bonc_auth.flask import AdminGuard


class FakeAuth:
    def verify(self, token):
        if token != "valid":
            from bonc_auth import InvalidToken
            raise InvalidToken()
        return {"adminId": "admin-1", "role": "Admin", "sessionId": "s1"}


def test_flask_blueprint_is_protected():
    app = Flask(__name__)
    bp = Blueprint("admin", __name__, url_prefix="/admin")
    AdminGuard(FakeAuth()).protect_blueprint(bp)

    @bp.get("/me")
    def me():
        return {"adminId": g.admin["adminId"]}

    app.register_blueprint(bp)
    client = app.test_client()
    assert client.get("/admin/me").status_code == 401
    response = client.get("/admin/me", headers={"Authorization": "Bearer valid"})
    assert response.status_code == 200
    assert response.json["adminId"] == "admin-1"
