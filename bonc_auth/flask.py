"""Small Flask Blueprint guard."""

from flask import Blueprint, current_app, g, jsonify, request

from .client import AuthServiceUnavailable, BoncAuth, Forbidden, InvalidToken, extract_bearer_token


class AdminGuard:
    """Protect all routes in a Flask admin Blueprint."""

    def __init__(self, auth: BoncAuth) -> None:
        self.auth = auth

    def protect_blueprint(self, blueprint: Blueprint) -> None:
        """Verify the Bearer token before each Blueprint request."""

        def verify_admin():
            # Browsers send OPTIONS before some cross-origin requests.
            if request.method == "OPTIONS":
                return None

            try:
                token = extract_bearer_token(request.headers.get("Authorization"))
                g.admin = self.auth.verify(token)
                return None
            except InvalidToken:
                return jsonify({"error": "Unauthorized"}), 401
            except Forbidden:
                return jsonify({"error": "Forbidden: Admin access required"}), 403
            except AuthServiceUnavailable as exc:
                current_app.logger.error("BONC auth service unavailable: %s", exc)
                return jsonify({"error": "Authentication service unavailable"}), 503

        blueprint.before_request(verify_admin)
