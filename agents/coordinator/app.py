"""The coordinator agent.

It delegates work to the specialist. The only thing that changes between the
baseline and the broker demonstration is DELEGATION_MODE, which decides whether
the call goes straight to the specialist carrying the coordinator's full
authority, or through the broker, which narrows it first.

That single switch is the point. Neither agent contains any scope logic.
"""

from __future__ import annotations

import base64
import logging
import os
import threading
import time
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import tracing

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("coordinator")

AGENT_NAME = os.environ.get("AGENT_NAME", "coordinator")

# "baseline" calls the specialist directly with the wide token.
# "broker" routes through the broker, which narrows the token first.
DELEGATION_MODE = os.environ.get("DELEGATION_MODE", "baseline").lower()

BROKER_URL = os.environ.get("BROKER_URL", "http://localhost:8081").rstrip("/")
SPECIALIST_URL = os.environ.get("SPECIALIST_URL", "http://localhost:8000").rstrip("/")

THUNDER_BASE_URL = os.environ.get("THUNDER_BASE_URL", "").rstrip("/")
CLIENT_ID = os.environ.get("COORDINATOR_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("COORDINATOR_CLIENT_SECRET", "")

# The coordinator's standing authority. This is the wide grant the broker
# narrows down, and on the baseline path it is what the specialist receives.
WIDE_SCOPES = os.environ.get(
    "COORDINATOR_SCOPES",
    "records:read records:list records:write",
).split()

SPECIALIST_RESOURCE = os.environ.get("SPECIALIST_RESOURCE", "https://specialist.agentid.local")

app = FastAPI(title="coordinator agent", version="0.1.0")

tracing.init_tracing(AGENT_NAME)


class ChatRequest(BaseModel):
    session_id: str = "default"
    message: str = ""


class DelegateRequest(BaseModel):
    task: str = ""
    capability: str
    depth: int = 0
    payload: dict[str, Any] = {}


class _TokenCache:
    """Caches the coordinator's wide token until shortly before it expires."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._token = ""
        self._expires_at = 0.0

    def get(self) -> str:
        with self._lock:
            if self._token and time.time() < self._expires_at - 30:
                return self._token

            if not THUNDER_BASE_URL or not CLIENT_ID:
                raise HTTPException(
                    status_code=500,
                    detail="THUNDER_BASE_URL and COORDINATOR_CLIENT_ID must be set",
                )

            basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
            response = httpx.post(
                f"{THUNDER_BASE_URL}/oauth2/token",
                data={
                    "grant_type": "client_credentials",
                    # Thunder only includes scopes that are explicitly
                    # requested, so an omitted scope yields an unscoped token.
                    "scope": " ".join(WIDE_SCOPES),
                    "resource": SPECIALIST_RESOURCE,
                },
                headers={"Authorization": f"Basic {basic}"},
                timeout=10.0,
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"could not get a coordinator token: {response.status_code} {response.text}",
                )

            body = response.json()
            self._token = body["access_token"]
            self._expires_at = time.time() + float(body.get("expires_in", 3600))

            granted = body.get("scope", "")
            log.info("coordinator token acquired with scope [%s]", granted)
            return self._token


_tokens = _TokenCache()


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "agent": AGENT_NAME, "mode": DELEGATION_MODE}


@app.post("/chat")
def chat(request: ChatRequest) -> dict[str, str]:
    """The Agent Manager chat contract."""
    return {
        "response": (
            f"{AGENT_NAME} delegates work to the specialist in {DELEGATION_MODE} mode. "
            "Post to /delegate to start one."
        )
    }


@app.post("/delegate")
def delegate(request: DelegateRequest) -> dict[str, Any]:
    """Delegate one task to the specialist, with or without the broker."""
    token = _tokens.get()

    with tracing.span(f"coordinator.delegate.{DELEGATION_MODE}") as sp:
        sp.set(tracing.ATTR_CAPABILITY, request.capability)
        sp.set(tracing.ATTR_TASK, request.task)
        sp.set(tracing.ATTR_DEPTH, request.depth)
        sp.set(tracing.ATTR_BROKER_ENABLED, DELEGATION_MODE == "broker")
        sp.set(tracing.ATTR_SCOPE_ORIGINAL, " ".join(WIDE_SCOPES))
        sp.set(tracing.ATTR_SCOPE_ORIGINAL_COUNT, len(WIDE_SCOPES))

        if DELEGATION_MODE == "broker":
            response = _via_broker(request, token)
        else:
            response = _direct(request, token)

        derived = response.headers.get("X-Broker-Derived-Scope", "")
        if derived:
            sp.set(tracing.ATTR_SCOPE_DERIVED, derived)
            sp.set(tracing.ATTR_SCOPE_DERIVED_COUNT, len(derived.split()))

        if response.status_code >= 400:
            sp.record_error(f"{response.status_code}")

        return {
            "mode": DELEGATION_MODE,
            "capability": request.capability,
            "status": response.status_code,
            "scopeSent": " ".join(WIDE_SCOPES) if DELEGATION_MODE != "broker" else None,
            "scopeDerived": derived or None,
            "response": _safe_json(response),
        }


def _direct(request: DelegateRequest, token: str) -> httpx.Response:
    """The baseline. The specialist receives the coordinator's full authority."""
    headers = tracing.inject({"Authorization": f"Bearer {token}"})
    return httpx.post(
        f"{SPECIALIST_URL}/capabilities/{request.capability}",
        json=request.payload,
        headers=headers,
        timeout=30.0,
    )


def _via_broker(request: DelegateRequest, token: str) -> httpx.Response:
    """The broker path. The specialist receives a token narrowed to this call."""
    headers = tracing.inject({"Authorization": f"Bearer {token}"})
    return httpx.post(
        f"{BROKER_URL}/delegate",
        json={
            "task": request.task,
            "capability": request.capability,
            "depth": request.depth,
            "payload": request.payload,
        },
        headers=headers,
        timeout=30.0,
    )


def _safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text
