"""The specialist agent.

It holds a small record store and exposes each operation on it as a separate
capability endpoint. Every capability endpoint declares the scope it needs, so
a token that was narrowed for reading cannot be replayed against writing.

The /chat endpoint exists so the agent matches the shape Agent Manager expects
of a platform hosted agent, which is what keeps registration and automatic
instrumentation working unchanged.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from auth import granted_scopes, require_scope

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("specialist")

app = FastAPI(title="specialist agent", version="0.1.0")

AGENT_NAME = os.environ.get("AGENT_NAME", "specialist")

# A stand in for whatever the specialist would really be guarding.
RECORDS: dict[str, dict[str, Any]] = {
    "42": {"id": "42", "subject": "Printer will not connect to wifi", "status": "open"},
    "43": {"id": "43", "subject": "Password reset request", "status": "closed"},
}


class ChatRequest(BaseModel):
    session_id: str = "default"
    message: str = ""


class RecordRef(BaseModel):
    recordId: str | None = None


class RecordWrite(BaseModel):
    recordId: str
    status: str | None = None
    subject: str | None = None


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "agent": AGENT_NAME}


@app.post("/chat")
def chat(request: ChatRequest) -> dict[str, str]:
    """The Agent Manager chat contract. Not part of the delegation path."""
    return {
        "response": (
            f"{AGENT_NAME} holds {len(RECORDS)} records. "
            "Delegated work arrives on the capability endpoints."
        )
    }


@app.post("/capabilities/records.read")
def records_read(body: RecordRef, claims: dict = require_scope("records.read")) -> dict[str, Any]:
    log.info("records.read by %s with scope [%s]", claims.get("sub"), claims.get("scope", ""))
    record = RECORDS.get(body.recordId or "")
    if record is None:
        return {"found": False, "recordId": body.recordId}
    return {"found": True, "record": record}


@app.post("/capabilities/records.list")
def records_list(claims: dict = require_scope("records.list")) -> dict[str, Any]:
    log.info("records.list by %s", claims.get("sub"))
    return {"records": [{"id": r["id"], "subject": r["subject"]} for r in RECORDS.values()]}


@app.post("/capabilities/records.summarise")
def records_summarise(
    body: RecordRef, claims: dict = require_scope("records.summarise")
) -> dict[str, Any]:
    log.info("records.summarise by %s", claims.get("sub"))
    record = RECORDS.get(body.recordId or "")
    if record is None:
        return {"found": False, "recordId": body.recordId}
    return {
        "found": True,
        "summary": f"Record {record['id']} is {record['status']} and concerns {record['subject']}.",
        "scopeUsed": granted_scopes(claims),
    }


@app.post("/capabilities/records.write")
def records_write(body: RecordWrite, claims: dict = require_scope("records.write")) -> dict[str, Any]:
    log.info("records.write by %s", claims.get("sub"))
    record = RECORDS.setdefault(body.recordId, {"id": body.recordId, "subject": "", "status": "open"})
    if body.status is not None:
        record["status"] = body.status
    if body.subject is not None:
        record["subject"] = body.subject
    return {"written": True, "record": record}
