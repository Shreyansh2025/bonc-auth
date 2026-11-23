"""Framework-independent models returned by the BONC verifier."""

from dataclasses import dataclass
from typing import Any, Mapping

from .exceptions import InvalidToken, InvalidVerificationResponse


def _as_string_set(value: Any, field_name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value}) if value else frozenset()
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return frozenset(item for item in value if item)
    raise InvalidVerificationResponse(
        f"Verification response field '{field_name}' must be a string or list of strings."
    )


@dataclass(frozen=True, slots=True)
class VerifiedUser:
    """Identity and access attributes returned by the trusted BONC service."""

    user_id: str
    roles: frozenset[str]
    permissions: frozenset[str]
    session_id: str | None = None

    @classmethod
    def from_response(
        cls,
        payload: Any,
        *,
        user_id_field: str = "adminId",
        role_field: str = "role",
        roles_field: str = "roles",
        permissions_field: str = "permissions",
        session_id_field: str = "sessionId",
        active_field: str | None = "active",
    ) -> "VerifiedUser":
        if not isinstance(payload, Mapping):
            raise InvalidVerificationResponse("Verification response must be a JSON object.")

        if active_field:
            active = payload.get(active_field)
            if active is False:
                raise InvalidToken("The BONC session is no longer active.")
            if active is not None and active is not True:
                raise InvalidVerificationResponse(
                    f"Verification response field '{active_field}' must be boolean."
                )

        user_id = payload.get(user_id_field)
        if not isinstance(user_id, (str, int)) or not str(user_id).strip():
            raise InvalidVerificationResponse(
                f"A successful response must contain a non-empty '{user_id_field}'."
            )

        roles = set(_as_string_set(payload.get(roles_field), roles_field))
        roles.update(_as_string_set(payload.get(role_field), role_field))
        permissions = _as_string_set(payload.get(permissions_field), permissions_field)

        session_value = payload.get(session_id_field)
        if session_value is not None and not isinstance(session_value, (str, int)):
            raise InvalidVerificationResponse(
                f"Verification response field '{session_id_field}' must be a string or integer."
            )

        return cls(
            user_id=str(user_id).strip(),
            roles=frozenset(roles),
            permissions=permissions,
            session_id=str(session_value) if session_value is not None else None,
        )

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions
