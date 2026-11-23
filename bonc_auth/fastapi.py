"""FastAPI dependency integration for bonc-auth."""

from fastapi import Depends, HTTPException, Request, status

from .client import BoncAuth
from .exceptions import AuthServiceUnavailable, InsufficientPermission, InvalidToken
from .models import VerifiedUser


class FastAPIBoncAuth:
    """Provide FastAPI dependencies backed by the central BONC verifier."""

    def __init__(self, auth: BoncAuth) -> None:
        self.auth = auth

    async def require_user(self, request: Request) -> VerifiedUser:
        """Return the verified identity or raise an HTTP error."""
        try:
            return await self.auth.authenticate_header_async(
                request.headers.get("Authorization")
            )
        except InvalidToken as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or inactive bearer token.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        except InsufficientPermission as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden.",
            ) from exc
        except AuthServiceUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable.",
            ) from exc

    def require_permission(self, permission: str):
        """Create a dependency requiring one permission."""
        async def dependency(
            user: VerifiedUser = Depends(self.require_user),
        ) -> VerifiedUser:
            if not user.has_permission(permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Required permission is missing.",
                )
            return user
        return dependency

    def require_role(self, role: str):
        """Create a dependency requiring one role."""
        async def dependency(
            user: VerifiedUser = Depends(self.require_user),
        ) -> VerifiedUser:
            if not user.has_role(role):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Required role is missing.",
                )
            return user
        return dependency
