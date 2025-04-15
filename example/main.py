from fastapi import FastAPI, Depends, Request
from msal_token_verification.middleware import JwtAuthMiddleware
from msal_token_verification.config import JwtIssuerConfig
import uvicorn

ad = JwtIssuerConfig(
    name="azuread",
    authority="https://login.microsoftonline.com/80fed762-7fe3-451e-8f24-3e26d72b77d3/",
    audience="api://eventellect.com/Eventellect.ArsenalFC",  # AD Client ID
    issuer="https://sts.windows.net/80fed762-7fe3-451e-8f24-3e26d72b77d3/",
    jwks_uri="https://login.microsoftonline.com/80fed762-7fe3-451e-8f24-3e26d72b77d3/discovery/keys",
)

app = FastAPI()
app.add_middleware(
    JwtAuthMiddleware,
    issuers=[ad],
    protect_prefixes=["/secure"],
)


@app.get("/public")
async def public_route():
    return {"message": "Public"}


@app.get("/secure")
async def secure_route(request: Request):
    user = request.state.user
    return {"message": "Authenticated", "user": user}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
