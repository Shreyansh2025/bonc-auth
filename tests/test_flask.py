import pytest
pytest.importorskip("flask")

from flask import Blueprint, Flask, g, jsonify

from bonc_auth.exceptions import AuthServiceUnavailable, InvalidToken
from bonc_auth.flask import FlaskBoncAuth
from bonc_auth.models import VerifiedUser


class FakeAuth:
    def authenticate_header(self, authorization):
        if authorization != "Bearer good-token":
            raise InvalidToken("invalid")
        return VerifiedUser(
            user_id="admin-1",
            roles=frozenset({"Admin"}),
            permissions=frozenset({"moderation.read"}),
        )


def test_blueprint_guard_allows_verified_admin():
    app = Flask(__name__)
    bp = Blueprint("admin", __name__, url_prefix="/api/admin")
    guard = FlaskBoncAuth(FakeAuth())
    guard.protect_blueprint(bp, required_role="Admin")

    @bp.get("/whoami")
    def whoami():
        return jsonify({"user_id": g.bonc_user.user_id})

    app.register_blueprint(bp)
    response = app.test_client().get(
        "/api/admin/whoami", headers={"Authorization": "Bearer good-token"}
    )
    assert response.status_code == 200
    assert response.json["user_id"] == "admin-1"


def test_blueprint_guard_rejects_missing_token():
    app = Flask(__name__)
    bp = Blueprint("admin", __name__, url_prefix="/api/admin")
    FlaskBoncAuth(FakeAuth()).protect_blueprint(bp)

    @bp.get("/data")
    def data():
        return {"ok": True}

    app.register_blueprint(bp)
    assert app.test_client().get("/api/admin/data").status_code == 401
