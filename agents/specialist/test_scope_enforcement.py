"""Proof that the narrowed scope is enforced, not decorative.

These are the two scenarios the project set out to demonstrate.

  1. The specialist is asked to do something outside the narrowed scope and
     refuses with 403.
  2. The specialist is asked to do something inside the narrowed scope and it
     succeeds.

The tokens here are signed with a real RSA key and verified through the same
code path production uses. Only the JWKS fetch is stubbed, so the signature,
issuer, audience and expiry checks are all genuinely exercised offline.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import auth
from app import app

ISSUER = "https://thunder.test"
AUDIENCE = "https://specialist.agentid.local"

# What the coordinator holds in the baseline: everything the specialist defines.
WIDE_SCOPES = [
    "records:read",
    "records:list",
    "records:write",
]

# What the broker derives for a read task.
NARROWED_SCOPES = ["records:read"]


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def stub_jwks(monkeypatch: pytest.MonkeyPatch, signing_key: rsa.RSAPrivateKey) -> None:
    """Serve the test key in place of a live ThunderID JWKS endpoint."""

    class _Key:
        key = signing_key.public_key()

    class _Client:
        def get_signing_key_from_jwt(self, token: str) -> _Key:
            return _Key()

    monkeypatch.setattr(auth, "_jwks", lambda: _Client())
    monkeypatch.setattr(auth, "THUNDER_ISSUER", ISSUER)
    monkeypatch.setattr(auth, "EXPECTED_AUDIENCE", AUDIENCE)
    monkeypatch.setattr(auth, "ALLOW_UNVERIFIED", False)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def mint(
    signing_key: rsa.RSAPrivateKey,
    scopes: list[str],
    *,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    lifetime: timedelta = timedelta(hours=1),
) -> str:
    now = datetime.now(tz=timezone.utc)
    claims = {
        "iss": issuer,
        "sub": "coordinator",
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + lifetime).timestamp()),
        "scope": " ".join(scopes),
        "sub_type": "agent",
    }
    return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "test-key"})


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# Scenario 1. Outside the narrowed scope, correctly denied.


def test_narrowed_token_cannot_write(client: TestClient, signing_key: rsa.RSAPrivateKey) -> None:
    token = mint(signing_key, NARROWED_SCOPES)

    response = client.post(
        "/capabilities/records.write",
        json={"recordId": "42", "status": "closed"},
        headers=bearer(token),
    )

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["error"] == "insufficient_scope"
    assert detail["required_scope"] == "records:write"
    assert "insufficient_scope" in response.headers["www-authenticate"]

    # The record must be untouched by the refused call.
    assert client.post(
        "/capabilities/records.read", json={"recordId": "42"}, headers=bearer(token)
    ).json()["record"]["status"] == "open"


def test_narrowed_token_cannot_list(client: TestClient, signing_key: rsa.RSAPrivateKey) -> None:
    """The read scope does not carry the list scope with it."""
    response = client.post(
        "/capabilities/records.list",
        json={},
        headers=bearer(mint(signing_key, NARROWED_SCOPES)),
    )
    assert response.status_code == 403


# Scenario 2. Inside the narrowed scope, succeeds.


def test_narrowed_token_can_read(client: TestClient, signing_key: rsa.RSAPrivateKey) -> None:
    response = client.post(
        "/capabilities/records.read",
        json={"recordId": "42"},
        headers=bearer(mint(signing_key, NARROWED_SCOPES)),
    )

    assert response.status_code == 200
    assert response.json()["record"]["id"] == "42"


def test_narrowed_token_can_summarise(client: TestClient, signing_key: rsa.RSAPrivateKey) -> None:
    """records.summarise needs read authority only, so the same token works."""
    response = client.post(
        "/capabilities/records.summarise",
        json={"recordId": "42"},
        headers=bearer(mint(signing_key, NARROWED_SCOPES)),
    )

    assert response.status_code == 200
    assert response.json()["scopeUsed"] == NARROWED_SCOPES


# The baseline, for contrast: a wide token can do everything, which is the
# behaviour the broker exists to remove.


def test_wide_token_can_write(client: TestClient, signing_key: rsa.RSAPrivateKey) -> None:
    response = client.post(
        "/capabilities/records.write",
        json={"recordId": "99", "subject": "Created by the baseline token"},
        headers=bearer(mint(signing_key, WIDE_SCOPES)),
    )

    assert response.status_code == 200
    assert response.json()["written"] is True


# Token level checks.


@pytest.mark.parametrize(
    ("name", "kwargs"),
    [
        ("wrong issuer", {"issuer": "https://attacker.test"}),
        ("wrong audience", {"audience": "some-other-service"}),
        ("expired", {"lifetime": timedelta(minutes=-5)}),
    ],
)
def test_bad_tokens_are_rejected(
    client: TestClient, signing_key: rsa.RSAPrivateKey, name: str, kwargs: dict
) -> None:
    response = client.post(
        "/capabilities/records.read",
        json={"recordId": "42"},
        headers=bearer(mint(signing_key, WIDE_SCOPES, **kwargs)),
    )
    assert response.status_code == 401, name


def test_token_signed_by_another_key_is_rejected(client: TestClient) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response = client.post(
        "/capabilities/records.read",
        json={"recordId": "42"},
        headers=bearer(mint(other, WIDE_SCOPES)),
    )
    assert response.status_code == 401


def test_missing_token_is_rejected(client: TestClient) -> None:
    response = client.post("/capabilities/records.read", json={"recordId": "42"})
    assert response.status_code == 401


def test_non_bearer_credential_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/capabilities/records.read",
        json={"recordId": "42"},
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert response.status_code == 401


def test_every_capability_declares_a_scope() -> None:
    """A capability endpoint without a declared scope must fail closed."""
    routes = {
        route.path.removeprefix("/capabilities/")
        for route in app.routes
        if getattr(route, "path", "").startswith("/capabilities/")
    }
    assert routes, "no capability routes found"
    assert routes <= set(auth.REQUIRED_SCOPES), (
        f"capabilities without a declared scope: {routes - set(auth.REQUIRED_SCOPES)}"
    )
