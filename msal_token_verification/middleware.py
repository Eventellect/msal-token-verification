import fnmatch
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from msal_token_verification.config import JwtIssuerConfig
from msal_token_verification.core import decode_jwt


class JwtAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        issuers: list[JwtIssuerConfig],
        *,
        allow_prefixes: list[str] = None,
        protect_prefixes: list[str] = None,
    ):
        super().__init__(app)
        self.issuers = issuers
        self.allow_prefixes = allow_prefixes or []
        self.protect_prefixes = protect_prefixes or []

    def get_token(self, request: Request) -> Optional[str]:
        # Check Authorization
        auth_value = None

        # Case-insensitive check for header name
        for key, value in request.headers.items():
            if key.lower() == "authorization":
                auth_value = value
                break

        if auth_value:
            # Case-insensitive check for Bearer prefix
            if auth_value.lower().startswith("bearer "):
                return auth_value[len("bearer ") :].strip()

        # # Check Cookie
        # for key, value in request.cookies.items():
        #     if key.lower() == "auth_token":
        #         return value

        return None

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        is_allowed = any(
            fnmatch.fnmatch(path, pattern) if "*" in pattern else path == pattern
            for pattern in self.allow_prefixes
        ) or (
            self.protect_prefixes
            and not any(
                fnmatch.fnmatch(path, pattern) if "*" in pattern else path == pattern
                for pattern in self.protect_prefixes
            )
        )
        if is_allowed:
            return await call_next(request)

        token = self.get_token(request)
        if not token:
            return JSONResponse(
                status_code=401, content={"detail": "Missing or invalid token"}
            )

        for config in self.issuers:
            try:
                payload = decode_jwt(token, config)
                request.state.user = payload
                return await call_next(request)
            except Exception:
                continue

        return JSONResponse(
            status_code=401, content={"detail": "Missing or invalid token"}
        )


def register_jwt_middleware(
    app: FastAPI,
    *,
    issuers: list[JwtIssuerConfig],
    allow_prefixes: list[str] = None,
    protect_prefixes: list[str] = None,
):
    if allow_prefixes and protect_prefixes:
        raise ValueError("allow_prefixes and protect_prefixes cannot be used together")

    app.add_middleware(
        JwtAuthMiddleware,
        issuers=issuers,
        allow_prefixes=allow_prefixes,
        protect_prefixes=protect_prefixes,
    )
