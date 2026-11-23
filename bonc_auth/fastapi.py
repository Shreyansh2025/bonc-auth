"""Small FastAPI admin dependency."""

from fastapi import HTTPException, Request, status

from .client import AuthServiceUnavailable, BoncAuth, Forbidden, InvalidToken, extract_bearer_token


class FastAPIAdminGuard:
    """Create a dependency that verifies the current admin on each request."""

    def __init__(self, auth: BoncAuth) -> None:
        self.auth = auth

    async def require_admin(self, request: Request) -> dict:
        try:
            token = extract_bearer_token(request.headers.get("Authorization"))
            return await self.auth.verify_async(token)
        except InvalidToken as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or inactive token.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        except Forbidden as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required.",
            ) from exc
        except AuthServiceUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable.",
            ) from exc
