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
        header_key: str = "Authorization",
    ):
        super().__init__(app)
        self.issuers = issuers
        self.allow_prefixes = allow_prefixes or []
        self.protect_prefixes = protect_prefixes or []
        self.header_key = header_key

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        is_allowed = any(path.startswith(prefix) for prefix in self.allow_prefixes) or (
            self.protect_prefixes
            and not any(path.startswith(prefix) for prefix in self.protect_prefixes)
        )
        if is_allowed:
            return await call_next(request)

        auth_header = request.headers.get(self.header_key)
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401, content={"detail": "Missing or invalid token"}
            )

        token = auth_header.split(" ")[1]
        try:
            unverified = jwt.get_unverified_claims(token)
            issuer = unverified.get("iss")
            for config in self.issuers:
                if config.issuer == issuer:
                    payload = decode_jwt(token, config)
                    request.state.user = payload
                    return await call_next(request)
        except JWTError:
            return JSONResponse(
                status_code=401, content={"detail": "Token validation failed"}
            )

        return JSONResponse(
            status_code=401, content={"detail": "Issuer not recognized"}
        )


def register_jwt_middleware(
    app: FastAPI,
    *,
    issuers: list[JwtIssuerConfig],
    allow_prefixes: list[str] = None,
    protect_prefixes: list[str] = None,
    header_key: str = "Authorization",
):
    if allow_prefixes and protect_prefixes:
        raise ValueError("allow_prefixes and protect_prefixes cannot be used together")

    app.add_middleware(
        JwtAuthMiddleware,
        issuers=issuers,
        allow_prefixes=allow_prefixes,
        protect_prefixes=protect_prefixes,
        header_key=header_key,
    )
