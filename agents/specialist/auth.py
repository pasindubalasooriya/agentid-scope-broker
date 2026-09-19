"""Scope enforcement for the specialist agent.

This is where the narrowing is actually enforced. It is worth being explicit
about why it lives here rather than in the gateway.

Agent Manager's AI Gateway applies a jwt-auth policy that checks the issuer and
the audience of a token and nothing else. It has no concept of a scope and
returns 401 on a bad signature, never 403 for missing authority. The Agent
Manager codebase reserves a future authorization policy for this but does not
implement one today. So a narrowed token would travel the product path without
anything looking at what was narrowed.

Putting the check in the callee is the honest way to show the narrowing is real.
In a production system this belongs in the gateway.
"""

from __future__ import annotations

import os
import time
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from jwt import PyJWKClient

# Which scope each capability demands. A capability that is not listed here is
# refused, so adding an endpoint without deciding its authority fails closed.
REQUIRED_SCOPES: dict[str, str] = {
    "records.read": "records:read",
    "records.list": "records:list",
    "records.write": "records:write",
    "records.summarise": "records:read",
}

THUNDER_BASE_URL = os.environ.get("THUNDER_BASE_URL", "").rstrip("/")
THUNDER_ISSUER = os.environ.get("THUNDER_ISSUER", THUNDER_BASE_URL).rstrip("/")
EXPECTED_AUDIENCE = os.environ.get("SPECIALIST_RESOURCE", "https://specialist.agentid.local")

# Setting this to true skips signature verification. It exists so the unit tests
# and a laptop demo can run without a live ThunderID, and it is never set in the
# deployed configuration.
ALLOW_UNVERIFIED = os.environ.get("ALLOW_UNVERIFIED_TOKENS", "").lower() == "true"

_jwk_client: PyJWKClient | None = None


def _jwks() -> PyJWKClient:
    """Return a cached JWKS client pointed at ThunderID."""
    global _jwk_client
    if _jwk_client is None:
        if not THUNDER_BASE_URL:
            raise RuntimeError("THUNDER_BASE_URL must be set to verify tokens")
        _jwk_client = PyJWKClient(f"{THUNDER_BASE_URL}/oauth2/jwks", cache_keys=True)
    return _jwk_client


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "invalid_token", "error_description": detail},
        headers={"WWW-Authenticate": 'Bearer realm="specialist", error="invalid_token"'},
    )


def _forbidden(required: str, held: list[str]) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "insufficient_scope",
            "error_description": f"this call requires {required}",
            "required_scope": required,
            "granted_scope": " ".join(held),
        },
        headers={
            "WWW-Authenticate": (
                'Bearer realm="specialist", error="insufficient_scope", '
                f'scope="{required}"'
            )
        },
    )


def bearer_token(request: Request) -> str:
    """Pull the raw bearer credential out of the Authorization header."""
    header = request.headers.get("authorization", "")
    if not header:
        raise _unauthorized("no bearer token")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise _unauthorized("expected a Bearer credential")
    return token.strip()


def verify_token(token: str) -> dict[str, Any]:
    """Verify a ThunderID access token and return its claims."""
    if ALLOW_UNVERIFIED:
        claims = jwt.decode(token, options={"verify_signature": False})
        if claims.get("exp") and time.time() > float(claims["exp"]):
            raise _unauthorized("token has expired")
        return claims

    try:
        signing_key = _jwks().get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=THUNDER_ISSUER or None,
            audience=EXPECTED_AUDIENCE,
            options={"require": ["exp", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise _unauthorized(str(exc)) from exc


def granted_scopes(claims: dict[str, Any]) -> list[str]:
    """Split the space delimited scope claim."""
    return str(claims.get("scope", "")).split()


def require_scope(capability: str):
    """Build a FastAPI dependency that enforces one capability's scope.

    Returns the verified claims so the handler can log who called it.
    """

    def dependency(request: Request) -> dict[str, Any]:
        required = REQUIRED_SCOPES.get(capability)
        if required is None:
            # An endpoint whose authority was never decided is not callable.
            raise _forbidden(f"<undeclared capability {capability}>", [])

        claims = verify_token(bearer_token(request))
        held = granted_scopes(claims)
        if required not in held:
            raise _forbidden(required, held)
        return claims

    return Depends(dependency)
