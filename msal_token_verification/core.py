import requests
from jose import jwt
from jose.exceptions import JWTError
from msal_token_verification.config import JwtIssuerConfig
from functools import lru_cache


@lru_cache
def get_jwks(jwks_uri: str) -> dict:
    response = requests.get(jwks_uri)
    response.raise_for_status()
    return response.json()


def decode_jwt(token: str, config: JwtIssuerConfig):
    jwks = get_jwks(config.jwks_uri)
    unverified = jwt.get_unverified_header(token)
    key = next((k for k in jwks["keys"] if k["kid"] == unverified["kid"]), None)
    if not key:
        raise JWTError("Public key not found")

    return jwt.decode(
        token, key, algorithms=["RS256"], audience=config.audience, issuer=config.issuer
    )
