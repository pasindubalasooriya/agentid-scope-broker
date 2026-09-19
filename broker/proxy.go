package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pasindubalasooriya/agentid-scope-broker/derivation"
)

// Headers the broker adds to the response so the before and after comparison is
// visible without decoding a token by hand.
const (
	HeaderOriginalScope = "X-Broker-Original-Scope"
	HeaderDerivedScope  = "X-Broker-Derived-Scope"
	HeaderCapability    = "X-Broker-Capability"
	HeaderDroppedScope  = "X-Broker-Dropped-Scope"
)

// DelegationRequest is the body the coordinator sends.
type DelegationRequest struct {
	Task       string          `json:"task"`
	Capability string          `json:"capability"`
	Depth      int             `json:"depth"`
	Payload    json.RawMessage `json:"payload"`
}

// Broker wires the verification, derivation, exchange and forwarding steps
// together.
type Broker struct {
	cfg      Config
	policy   derivation.Policy
	verifier *Verifier
	thunder  *ThunderClient
	client   *http.Client
	log      *slog.Logger
	tracer   Tracer
}

// NewBroker builds a broker from validated configuration.
func NewBroker(cfg Config, policy derivation.Policy, log *slog.Logger, tracer Tracer) *Broker {
	return &Broker{
		cfg:      cfg,
		policy:   policy,
		verifier: NewVerifier(cfg.JWKSEndpoint(), cfg.ThunderIssuer, &http.Client{Timeout: cfg.ThunderTimeout}),
		thunder:  NewThunderClient(cfg.TokenEndpoint(), cfg.BrokerClientID, cfg.BrokerClientSecret, cfg.ThunderTimeout),
		client:   &http.Client{Timeout: cfg.ForwardTimeout},
		log:      log,
		tracer:   tracer,
	}
}

// Routes builds the broker's HTTP surface.
func (b *Broker) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /delegate", b.handleDelegate)
	mux.HandleFunc("GET /healthz", b.handleHealth)
	return mux
}

func (b *Broker) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := b.verifier.Refresh(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unavailable",
			"reason": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (b *Broker) handleDelegate(w http.ResponseWriter, r *http.Request) {
	// Join the caller's trace before starting our span, so the coordinator, the
	// broker and the specialist all appear as one delegation rather than three
	// unrelated traces.
	ctx, span := b.tracer.Start(b.tracer.Extract(r.Context(), r.Header), "broker.delegate")
	defer span.End()

	// 1. Read and validate the delegation request.
	var req DelegationRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		b.fail(w, span, http.StatusBadRequest, "invalid_request", fmt.Sprintf("malformed body: %v", err))
		return
	}
	if strings.TrimSpace(req.Capability) == "" {
		b.fail(w, span, http.StatusBadRequest, "invalid_request", "capability is required")
		return
	}
	if req.Depth < 0 {
		b.fail(w, span, http.StatusBadRequest, "invalid_request", "depth must not be negative")
		return
	}

	span.SetString(AttrCapability, req.Capability)
	span.SetString(AttrTask, req.Task)
	span.SetInt(AttrDepth, req.Depth)
	span.SetBool(AttrBrokerEnabled, true)

	// 2. Verify the coordinator's token and read what it actually holds.
	raw, err := BearerToken(r.Header.Get("Authorization"))
	if err != nil {
		b.fail(w, span, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}
	claims, err := b.verifier.Verify(ctx, raw)
	if err != nil {
		b.fail(w, span, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	original := claims.Scopes()
	// Set early so the comparison header is present on refusals too, not only
	// on the happy path.
	w.Header().Set(HeaderOriginalScope, strings.Join(original, " "))
	span.SetString(AttrScopeOriginal, strings.Join(original, " "))
	span.SetInt(AttrScopeOriginalCount, len(original))
	span.SetString(AttrSubject, claims.Subject)

	// 3. Derive the narrowed set.
	result, err := derivation.Derive(derivation.DelegationContext{
		Task:       req.Task,
		Capability: req.Capability,
		Depth:      req.Depth,
		Available:  original,
	}, b.policy)
	if err != nil {
		status, code := derivationStatus(err)
		b.fail(w, span, status, code, err.Error())
		return
	}

	span.SetString(AttrScopeDerived, result.String())
	span.SetInt(AttrScopeDerivedCount, len(result.Scopes))
	if len(result.Dropped) > 0 {
		span.SetString(AttrScopeDropped, formatDropped(result.Dropped))
	}

	// 4. Exchange for a token carrying exactly that set.
	token, err := b.thunder.Exchange(ctx, raw, result)
	if err != nil {
		code := "exchange_failed"
		if errors.Is(err, ErrScopeNotHonoured) {
			code = "scope_not_honoured"
		}
		b.fail(w, span, http.StatusBadGateway, code, err.Error())
		return
	}

	// Logged as one self contained line: what the caller held, what the policy
	// derived for this call, and what Thunder actually issued. All three are
	// needed to see that the narrowing happened and was honoured.
	b.log.Info("narrowed delegation",
		"capability", req.Capability,
		"depth", req.Depth,
		"subject", claims.Subject,
		"original_scope", strings.Join(original, " "),
		"original_scope_count", len(original),
		"derived_scope", result.String(),
		"derived_scope_count", len(result.Scopes),
		"issued_scope", strings.Join(token.Scopes, " "),
		"resource", result.Resource,
		"expires_in", token.ExpiresIn,
	)

	// 5. Forward to the specialist with the narrowed token.
	b.forward(ctx, w, span, req, result, token)
}

// forward sends the payload on to the specialist and copies its reply back.
func (b *Broker) forward(
	ctx context.Context,
	w http.ResponseWriter,
	span Span,
	req DelegationRequest,
	result derivation.Result,
	token ExchangedToken,
) {
	target := b.cfg.SpecialistURL + "/capabilities/" + url.PathEscape(req.Capability)

	payload := req.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}

	outbound, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		b.fail(w, span, http.StatusInternalServerError, "forward_failed", err.Error())
		return
	}
	outbound.Header.Set("Content-Type", "application/json")
	outbound.Header.Set("Authorization", "Bearer "+token.AccessToken)
	b.tracer.Inject(ctx, outbound.Header)

	resp, err := b.client.Do(outbound)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		b.fail(w, span, status, "forward_failed", err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		b.fail(w, span, http.StatusBadGateway, "forward_failed", fmt.Sprintf("read specialist response: %v", err))
		return
	}

	span.SetInt(AttrSpecialistStatus, resp.StatusCode)

	b.setScopeHeaders(w, req, result, token)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(body); err != nil {
		b.log.Warn("writing response to coordinator failed", "error", err)
	}
}

func (b *Broker) setScopeHeaders(w http.ResponseWriter, req DelegationRequest, result derivation.Result, token ExchangedToken) {
	w.Header().Set(HeaderCapability, req.Capability)
	w.Header().Set(HeaderDerivedScope, strings.Join(token.Scopes, " "))
	if len(result.Dropped) > 0 {
		w.Header().Set(HeaderDroppedScope, formatDropped(result.Dropped))
	}
}

// fail records the failure on the span and answers the coordinator with an
// OAuth style error body.
func (b *Broker) fail(w http.ResponseWriter, span Span, status int, code, description string) {
	span.SetString(AttrError, code)
	span.RecordError(errors.New(description))

	b.log.Warn("delegation refused", "status", status, "code", code, "detail", description)

	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer realm="agentid-scope-broker", error=%q`, code))
	}
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// derivationStatus maps a derivation error onto an HTTP status and error code.
func derivationStatus(err error) (int, string) {
	switch {
	case errors.Is(err, derivation.ErrUnknownCapability):
		return http.StatusForbidden, "unknown_capability"
	case errors.Is(err, derivation.ErrDepthExceeded):
		return http.StatusForbidden, "depth_exceeded"
	case errors.Is(err, derivation.ErrNoScopes):
		return http.StatusForbidden, "insufficient_scope"
	case errors.Is(err, derivation.ErrNegativeDepth):
		return http.StatusBadRequest, "invalid_request"
	default:
		return http.StatusInternalServerError, "derivation_failed"
	}
}

func formatDropped(dropped []derivation.DroppedScope) string {
	parts := make([]string, 0, len(dropped))
	for _, d := range dropped {
		parts = append(parts, d.Name+" ("+d.Reason+")")
	}
	return strings.Join(parts, ", ")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
