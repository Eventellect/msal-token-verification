from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from msal_token_verification.config import JwtIssuerConfig
from msal_token_verification.core import decode_jwt


class JwtAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        issuers: list[JwtIssuerConfig],
        header_key: str = "Authorization",
        bypass_paths: list[str] = None,
    ):
        super().__init__(app)
        self.issuers = issuers
        self.header_key = header_key
        self.bypass_paths = bypass_paths or []

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.bypass_paths:
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
