package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Span attribute names.
//
// The same names are set on the baseline path and the broker path so the two
// traces can be read side by side. On the baseline, agentid.broker.enabled is
// false and agentid.scope.derived is absent, which is the whole comparison in
// two attributes.
const (
	AttrScopeOriginal      = "agentid.scope.original"
	AttrScopeOriginalCount = "agentid.scope.original.count"
	AttrScopeDerived       = "agentid.scope.derived"
	AttrScopeDerivedCount  = "agentid.scope.derived.count"
	AttrScopeDropped       = "agentid.scope.dropped"
	AttrCapability         = "agentid.capability"
	AttrTask               = "agentid.task"
	AttrDepth              = "agentid.delegation.depth"
	AttrBrokerEnabled      = "agentid.broker.enabled"
	AttrSubject            = "agentid.subject"
	AttrSpecialistStatus   = "agentid.specialist.status"
	AttrError              = "agentid.error"
)

// Span is the small slice of tracing the broker needs. Keeping it behind an
// interface means the request path stays testable without a collector.
type Span interface {
	SetString(key, value string)
	SetInt(key string, value int)
	SetBool(key string, value bool)
	RecordError(err error)
	End()
}

// Tracer starts spans and carries trace context across the delegation.
type Tracer interface {
	// Extract reads inbound W3C trace context, so the broker's work joins the
	// caller's trace rather than starting a disconnected one.
	Extract(ctx context.Context, header http.Header) context.Context
	Start(ctx context.Context, name string) (context.Context, Span)
	Inject(ctx context.Context, header http.Header)
	Shutdown(ctx context.Context) error
}

// NewTracer returns an OTLP backed tracer, or a no-op one when no endpoint is
// configured. A missing endpoint disables tracing rather than failing startup,
// matching how Agent Manager's own instrumentation behaves.
func NewTracer(ctx context.Context, cfg Config) (Tracer, error) {
	if cfg.OTLPEndpoint == "" {
		return noopTracer{}, nil
	}

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(cfg.OTLPEndpoint + "/v1/traces"),
	}
	// Agent Manager's collector sits behind the gateway, which authenticates
	// with the agent API key rather than a bearer token.
	if cfg.AgentAPIKey != "" {
		opts = append(opts, otlptracehttp.WithHeaders(map[string]string{
			"x-amp-api-key": cfg.AgentAPIKey,
		}))
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("build otlp exporter: %w", err)
	}

	// NewSchemaless, not NewWithAttributes, on purpose. resource.Default()
	// carries the SDK's own schema URL, and Merge fails outright when the two
	// sides disagree. Pinning a semconv version here would mean this breaks
	// again on the next SDK upgrade.
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName(cfg.ServiceName),
	))
	if err != nil {
		return nil, fmt.Errorf("build trace resource: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(provider)

	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(propagator)

	return &otelTracer{
		tracer:     provider.Tracer("agentid-scope-broker"),
		provider:   provider,
		propagator: propagator,
	}, nil
}

type otelTracer struct {
	tracer     trace.Tracer
	provider   *sdktrace.TracerProvider
	propagator propagation.TextMapPropagator
}

func (t *otelTracer) Start(ctx context.Context, name string) (context.Context, Span) {
	ctx, span := t.tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindServer))
	return ctx, otelSpan{span}
}

func (t *otelTracer) Extract(ctx context.Context, header http.Header) context.Context {
	return t.propagator.Extract(ctx, propagation.HeaderCarrier(header))
}

func (t *otelTracer) Inject(ctx context.Context, header http.Header) {
	t.propagator.Inject(ctx, propagation.HeaderCarrier(header))
}

func (t *otelTracer) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return t.provider.Shutdown(ctx)
}

type otelSpan struct{ span trace.Span }

func (s otelSpan) SetString(key, value string) {
	s.span.SetAttributes(attribute.String(key, value))
}

func (s otelSpan) SetInt(key string, value int) {
	s.span.SetAttributes(attribute.Int(key, value))
}

func (s otelSpan) SetBool(key string, value bool) {
	s.span.SetAttributes(attribute.Bool(key, value))
}

func (s otelSpan) RecordError(err error) {
	s.span.RecordError(err)
	s.span.SetStatus(codes.Error, err.Error())
}

func (s otelSpan) End() { s.span.End() }

// noopTracer is used when tracing is not configured, and in unit tests.
type noopTracer struct{}

func (noopTracer) Start(ctx context.Context, _ string) (context.Context, Span) {
	return ctx, noopSpan{}
}
func (noopTracer) Extract(ctx context.Context, _ http.Header) context.Context { return ctx }
func (noopTracer) Inject(context.Context, http.Header)                        {}
func (noopTracer) Shutdown(context.Context) error                             { return nil }

type noopSpan struct{}

func (noopSpan) SetString(string, string) {}
func (noopSpan) SetInt(string, int)       {}
func (noopSpan) SetBool(string, bool)     {}
func (noopSpan) RecordError(error)        {}
func (noopSpan) End()                     {}
