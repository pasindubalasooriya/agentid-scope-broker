"""Tracing for the coordinator.

The point of this module is that the baseline call and the broker routed call
carry the same attribute names, so the two traces can be read side by side. On
the baseline, agentid.broker.enabled is false and agentid.scope.derived is
absent, which is the entire comparison in two attributes.

Tracing is optional. With no OTLP endpoint configured the helpers become no-ops
rather than failing, which matches how Agent Manager's own instrumentation
behaves.
"""

from __future__ import annotations

import contextlib
import logging
import os
from typing import Any, Iterator

log = logging.getLogger("coordinator.tracing")

# Attribute names, kept identical to the Go broker's trace.go.
ATTR_SCOPE_ORIGINAL = "agentid.scope.original"
ATTR_SCOPE_ORIGINAL_COUNT = "agentid.scope.original.count"
ATTR_SCOPE_DERIVED = "agentid.scope.derived"
ATTR_SCOPE_DERIVED_COUNT = "agentid.scope.derived.count"
ATTR_CAPABILITY = "agentid.capability"
ATTR_TASK = "agentid.task"
ATTR_DEPTH = "agentid.delegation.depth"
ATTR_BROKER_ENABLED = "agentid.broker.enabled"
ATTR_ERROR = "agentid.error"

_tracer: Any = None


def init_tracing(service_name: str) -> None:
    """Set up OTLP export if an endpoint is configured."""
    global _tracer

    endpoint = os.environ.get("AMP_OTEL_ENDPOINT", "").rstrip("/")
    if not endpoint:
        log.info("no AMP_OTEL_ENDPOINT set, tracing disabled")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        headers = {}
        api_key = os.environ.get("AMP_AGENT_API_KEY", "")
        if api_key:
            # Agent Manager's collector sits behind the gateway, which
            # authenticates with the agent API key rather than a bearer token.
            headers["x-amp-api-key"] = api_key

        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces", headers=headers)
            )
        )
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(service_name)
        log.info("tracing enabled, exporting to %s", endpoint)
    except Exception:
        # Never let telemetry setup take the agent down.
        log.exception("tracing setup failed, continuing without it")


@contextlib.contextmanager
def span(name: str) -> Iterator["SpanHandle"]:
    """Start a span, or yield a no-op handle when tracing is off."""
    if _tracer is None:
        yield SpanHandle(None)
        return

    with _tracer.start_as_current_span(name) as raw:
        yield SpanHandle(raw)


def inject(headers: dict[str, str]) -> dict[str, str]:
    """Add W3C trace context so the broker's spans join this trace."""
    if _tracer is None:
        return headers
    try:
        from opentelemetry.propagate import inject as otel_inject

        otel_inject(headers)
    except Exception:
        log.debug("trace context injection failed", exc_info=True)
    return headers


class SpanHandle:
    """A thin wrapper so callers never need to check whether tracing is on."""

    def __init__(self, raw: Any) -> None:
        self._raw = raw

    def set(self, key: str, value: Any) -> None:
        if self._raw is None:
            return
        with contextlib.suppress(Exception):
            self._raw.set_attribute(key, value)

    def record_error(self, message: str) -> None:
        self.set(ATTR_ERROR, message)
