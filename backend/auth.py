import os
import requests
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

# Public URL — what a browser/frontend uses to log in
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
# Internal URL — used by the backend container to reach Keycloak over the Docker network
KEYCLOAK_INTERNAL_URL = os.getenv("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "soc-platform")

# Tokens can carry either issuer depending on which URL the caller used to reach
# Keycloak (browser -> KEYCLOAK_URL, internal services like n8n -> KEYCLOAK_INTERNAL_URL).
# Accept both so a valid token isn't rejected just because of which hostname issued it.
ACCEPTED_ISSUERS = [
    f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}",
    f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}",
]

security = HTTPBearer()
_jwks_cache = None

def get_jwks(force_refresh: bool = False):
    global _jwks_cache
    if _jwks_cache is None or force_refresh:
        url = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
        _jwks_cache = requests.get(url, timeout=10).json()
    return _jwks_cache

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]

        jwks = get_jwks()
        key = next((k for k in jwks["keys"] if k["kid"] == kid), None)

        if key is None:
            jwks = get_jwks(force_refresh=True)
            key = next((k for k in jwks["keys"] if k["kid"] == kid), None)

        if key is None:
            raise HTTPException(status_code=401, detail="Invalid token: signing key not found")

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience="account",
            issuer=ACCEPTED_ISSUERS,
        )
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid or expired token: {str(e)}")

def require_role(required_role: str):
    def role_checker(payload: dict = Depends(verify_token)):
        roles = payload.get("realm_access", {}).get("roles", [])
        if required_role not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {required_role}")
        return payload
    return role_checker

def verify_token_string(token: str) -> dict:
    """Same verification logic as verify_token, but takes a raw token string —
    used by WebSocket routes since they can't use HTTPBearer/Depends the normal way."""
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]

        jwks = get_jwks()
        key = next((k for k in jwks["keys"] if k["kid"] == kid), None)

        if key is None:
            jwks = get_jwks(force_refresh=True)
            key = next((k for k in jwks["keys"] if k["kid"] == kid), None)

        if key is None:
            raise ValueError("Invalid token: signing key not found")

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience="account",
            issuer=ACCEPTED_ISSUERS,
        )
        return payload
    except (JWTError, ValueError) as e:
        raise ValueError(f"Invalid or expired token: {str(e)}")