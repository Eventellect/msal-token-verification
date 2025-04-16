from pydantic import BaseModel


class JwtIssuerConfig(BaseModel):
    name: str
    authority: str
    audience: str
    issuer: str
    jwks_uri: str
