import pytest

from bonc_auth.exceptions import InvalidToken, InvalidVerificationResponse
from bonc_auth.models import VerifiedUser


def test_parses_example_dotnet_response():
    user = VerifiedUser.from_response(
        {"adminId": "admin-123", "role": "Admin", "sessionId": "session-1"}
    )
    assert user.user_id == "admin-123"
    assert user.has_role("Admin")
    assert user.session_id == "session-1"


def test_parses_alternative_response_fields():
    user = VerifiedUser.from_response(
        {
            "active": True,
            "user_id": "user-123",
            "roles": ["Admin", "Moderator"],
            "permissions": ["moderation.read"],
        },
        user_id_field="user_id",
        role_field="role",
        roles_field="roles",
        active_field="active",
    )
    assert user.has_role("Moderator")
    assert user.has_permission("moderation.read")


def test_inactive_session_is_rejected():
    with pytest.raises(InvalidToken):
        VerifiedUser.from_response(
            {"active": False, "adminId": "admin-1"}, active_field="active"
        )


def test_response_without_user_id_is_rejected():
    with pytest.raises(InvalidVerificationResponse):
        VerifiedUser.from_response({"role": "Admin"})


def test_roles_must_be_strings_or_list_of_strings():
    with pytest.raises(InvalidVerificationResponse):
        VerifiedUser.from_response({"adminId": "admin-1", "role": 42})
