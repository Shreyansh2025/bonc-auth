"""Flask Blueprint integration for bonc-auth."""

from functools import wraps
from typing import Any, Callable

from flask import Blueprint, current_app, g, jsonify, request

from .client import BoncAuth
from .exceptions import AuthServiceUnavailable, InsufficientPermission, InvalidToken
from .models import VerifiedUser


def _error_response(error: Exception):
    if isinstance(error, InvalidToken):
        return jsonify({"error": "unauthorized"}), 401
    if isinstance(error, InsufficientPermission):
        return jsonify({"error": "forbidden"}), 403
    if isinstance(error, AuthServiceUnavailable):
        current_app.logger.error("BONC authentication service unavailable: %s", error)
        return jsonify({"error": "authentication_service_unavailable"}), 503
    raise error


class FlaskBoncAuth:
    """Protect Flask Blueprints and expose the verified user as ``g.bonc_user``."""

    def __init__(self, auth: BoncAuth) -> None:
        self.auth = auth

    def protect_blueprint(
        self,
        blueprint: Blueprint,
        *,
        required_role: str | None = None,
        required_permission: str | None = None,
        allow_options: bool = True,
    ) -> None:
        """Attach authentication to every request handled by a Blueprint."""

        def verify_request():
            if allow_options and request.method == "OPTIONS":
                return None
            try:
                user = self.auth.authenticate_header(request.headers.get("Authorization"))
                if required_role and not user.has_role(required_role):
                    raise InsufficientPermission("Required role is missing.")
                if required_permission and not user.has_permission(required_permission):
                    raise InsufficientPermission("Required permission is missing.")
                g.bonc_user = user
                return None
            except (InvalidToken, InsufficientPermission, AuthServiceUnavailable) as exc:
                return _error_response(exc)

        blueprint.before_request(verify_request)

    @staticmethod
    def require_permission(permission: str) -> Callable:
        """Protect one route using a permission returned by BONC."""
        def decorator(view: Callable) -> Callable:
            @wraps(view)
            def wrapped(*args: Any, **kwargs: Any):
                user: VerifiedUser | None = getattr(g, "bonc_user", None)
                if user is None:
                    return jsonify({"error": "unauthorized"}), 401
                if not user.has_permission(permission):
                    return jsonify({"error": "forbidden"}), 403
                return view(*args, **kwargs)
            return wrapped
        return decorator

    @staticmethod
    def require_role(role: str) -> Callable:
        """Protect one route using a role returned by BONC."""
        def decorator(view: Callable) -> Callable:
            @wraps(view)
            def wrapped(*args: Any, **kwargs: Any):
                user: VerifiedUser | None = getattr(g, "bonc_user", None)
                if user is None:
                    return jsonify({"error": "unauthorized"}), 401
                if not user.has_role(role):
                    return jsonify({"error": "forbidden"}), 403
                return view(*args, **kwargs)
            return wrapped
        return decorator
