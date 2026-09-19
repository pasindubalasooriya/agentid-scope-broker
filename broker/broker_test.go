package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pasindubalasooriya/agentid-scope-broker/derivation"
)

const testKID = "test-signing-key"

// wideScopes is the coordinator's standing authority in the baseline.
var wideScopes = []string{
	"records:read",
	"records:list",
	"records:write",
}

// harness is a whole broker wired to stubbed versions of everything it talks to.
type harness struct {
	t *testing.T

	key    *rsa.PrivateKey
	issuer string

	broker *httptest.Server

	// exchangeScopeOverride, when set, is what the stub Thunder puts in the
	// issued token regardless of what was asked for. It exists to reproduce
	// Thunder's silent scope dropping.
	exchangeScopeOverride *string

	// lastExchange records the form the broker posted to the token endpoint.
	lastExchange url.Values

	// specialistAuth records the Authorization header the specialist received.
	specialistAuth   string
	specialistStatus int
	specialistBody   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	h := &harness{
		t:                t,
		key:              key,
		specialistStatus: http.StatusOK,
		specialistBody:   `{"result":"ok"}`,
	}

	// Stub ThunderID: publishes a JWKS and performs token exchange.
	thunder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/jwks":
			h.serveJWKS(w)
		case "/oauth2/token":
			h.serveTokenExchange(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(thunder.Close)
	h.issuer = thunder.URL

	// Stub specialist.
	specialist := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.specialistAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(h.specialistStatus)
		_, _ = io.WriteString(w, h.specialistBody)
	}))
	t.Cleanup(specialist.Close)

	policy, err := derivation.DefaultPolicy()
	if err != nil {
		t.Fatalf("DefaultPolicy: %v", err)
	}

	cfg := Config{
		Addr:               ":0",
		ThunderBaseURL:     thunder.URL,
		ThunderIssuer:      thunder.URL,
		BrokerClientID:     "broker-client",
		BrokerClientSecret: "broker-secret",
		SpecialistURL:      specialist.URL,
		ForwardTimeout:     5 * time.Second,
		ThunderTimeout:     5 * time.Second,
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := NewBroker(cfg, policy, log, noopTracer{})

	h.broker = httptest.NewServer(b.Routes())
	t.Cleanup(h.broker.Close)

	return h
}

func (h *harness) serveJWKS(w http.ResponseWriter) {
	pub := h.key.Public().(*rsa.PublicKey)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": testKID,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
		}},
	})
}

func (h *harness) serveTokenExchange(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	h.lastExchange = r.PostForm

	id, secret, ok := r.BasicAuth()
	if !ok || id != "broker-client" || secret != "broker-secret" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
		return
	}

	issuedScope := r.PostForm.Get("scope")
	if h.exchangeScopeOverride != nil {
		issuedScope = *h.exchangeScopeOverride
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      h.mintToken(strings.Fields(issuedScope), time.Hour),
		"token_type":        "Bearer",
		"scope":             issuedScope,
		"expires_in":        3600,
		"issued_token_type": TokenTypeAccessToken,
	})
}

// mintToken builds an RS256 token signed with the harness key.
func (h *harness) mintToken(scopes []string, ttl time.Duration) string {
	return h.mintTokenWithKID(testKID, scopes, ttl)
}

func (h *harness) mintTokenWithKID(kid string, scopes []string, ttl time.Duration) string {
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	claims := map[string]any{
		"iss":      h.issuer,
		"sub":      "coordinator",
		"aud":      "https://specialist.agentid.local",
		"exp":      time.Now().Add(ttl).Unix(),
		"iat":      time.Now().Unix(),
		"scope":    strings.Join(scopes, " "),
		"sub_type": "agent",
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, h.key, crypto.SHA256, digest[:])
	if err != nil {
		h.t.Fatalf("sign token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// delegate posts a delegation request with the given bearer token.
func (h *harness) delegate(token string, body map[string]any) *http.Response {
	h.t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		h.t.Fatalf("marshal body: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, h.broker.URL+"/delegate", strings.NewReader(string(raw)))
	if err != nil {
		h.t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := h.broker.Client().Do(req)
	if err != nil {
		h.t.Fatalf("delegate: %v", err)
	}
	h.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return payload.Error
}

// TestDelegateNarrowsTheToken is the end to end claim of the project, exercised
// against stubs: a read task reaches the specialist carrying read authority
// only, even though the caller held write authority too.
func TestDelegateNarrowsTheToken(t *testing.T) {
	h := newHarness(t)
	subject := h.mintToken(wideScopes, time.Hour)

	resp := h.delegate(subject, map[string]any{
		"task":       "summarise record 42",
		"capability": "records.summarise",
		"depth":      0,
		"payload":    map[string]string{"recordId": "42"},
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", resp.StatusCode, errorCode(t, resp))
	}

	original := resp.Header.Get(HeaderOriginalScope)
	derived := resp.Header.Get(HeaderDerivedScope)

	if derived != "records:read" {
		t.Errorf("derived scope = %q, want %q", derived, "records:read")
	}
	if len(strings.Fields(derived)) >= len(strings.Fields(original)) {
		t.Errorf("derived scope %q is not narrower than original %q", derived, original)
	}
	if strings.Contains(derived, "write") {
		t.Errorf("a read task derived write authority: %q", derived)
	}

	// The specialist must receive the narrowed token, never the caller's.
	got := strings.TrimPrefix(h.specialistAuth, "Bearer ")
	if got == subject {
		t.Error("the specialist received the coordinator's original token")
	}
	claims := decodeClaims(t, got)
	if claims.Scope != "records:read" {
		t.Errorf("forwarded token scope = %q, want %q", claims.Scope, "records:read")
	}

	// And the exchange must have been a real RFC 8693 call bound to the policy
	// resource rather than a fresh client credentials token.
	if grant := h.lastExchange.Get("grant_type"); grant != GrantTypeTokenExchange {
		t.Errorf("grant_type = %q, want %q", grant, GrantTypeTokenExchange)
	}
	if res := h.lastExchange.Get("resource"); res != "https://specialist.agentid.local" {
		t.Errorf("resource = %q, want %q", res, "https://specialist.agentid.local")
	}
	if h.lastExchange.Get("subject_token") != subject {
		t.Error("the exchange did not present the coordinator's token as the subject")
	}
	if h.lastExchange.Has("audience") {
		t.Error("audience was sent, but Thunder ignores it for the issued token")
	}
}

// TestScopeSilentlyDroppedIsRejected covers the failure mode that is easiest to
// miss: Thunder returns 200 with a shorter scope than was asked for.
func TestScopeSilentlyDroppedIsRejected(t *testing.T) {
	h := newHarness(t)

	// The broker will ask for read and list. Thunder answers with read only.
	dropped := "records:read"
	h.exchangeScopeOverride = &dropped

	resp := h.delegate(h.mintToken(wideScopes, time.Hour), map[string]any{
		"capability": "records.read",
		"depth":      0,
	})

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if code := errorCode(t, resp); code != "scope_not_honoured" {
		t.Errorf("error = %q, want %q", code, "scope_not_honoured")
	}
	if h.specialistAuth != "" {
		t.Error("the broker forwarded the call despite an unhonoured scope")
	}
}

func TestDelegateRejections(t *testing.T) {
	tests := []struct {
		name       string
		token      func(h *harness) string
		body       map[string]any
		wantStatus int
		wantCode   string
	}{
		{
			name:       "missing token",
			token:      func(*harness) string { return "" },
			body:       map[string]any{"capability": "records.read"},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_token",
		},
		{
			name:       "token signed by an unknown key",
			token:      func(h *harness) string { return h.mintTokenWithKID("other-key", wideScopes, time.Hour) },
			body:       map[string]any{"capability": "records.read"},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_token",
		},
		{
			name:       "expired token",
			token:      func(h *harness) string { return h.mintToken(wideScopes, -time.Minute) },
			body:       map[string]any{"capability": "records.read"},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_token",
		},
		{
			name:       "unknown capability fails closed",
			token:      func(h *harness) string { return h.mintToken(wideScopes, time.Hour) },
			body:       map[string]any{"capability": "records.delete"},
			wantStatus: http.StatusForbidden,
			wantCode:   "unknown_capability",
		},
		{
			name:       "write refused once delegated onward",
			token:      func(h *harness) string { return h.mintToken(wideScopes, time.Hour) },
			body:       map[string]any{"capability": "records.write", "depth": 1},
			wantStatus: http.StatusForbidden,
			wantCode:   "depth_exceeded",
		},
		{
			name:       "caller cannot delegate authority it lacks",
			token:      func(h *harness) string { return h.mintToken([]string{"records:read"}, time.Hour) },
			body:       map[string]any{"capability": "records.write"},
			wantStatus: http.StatusForbidden,
			wantCode:   "insufficient_scope",
		},
		{
			name:       "missing capability",
			token:      func(h *harness) string { return h.mintToken(wideScopes, time.Hour) },
			body:       map[string]any{"task": "do something"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "negative depth",
			token:      func(h *harness) string { return h.mintToken(wideScopes, time.Hour) },
			body:       map[string]any{"capability": "records.read", "depth": -1},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			resp := h.delegate(tt.token(h), tt.body)

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if code := errorCode(t, resp); code != tt.wantCode {
				t.Errorf("error = %q, want %q", code, tt.wantCode)
			}
			if h.specialistAuth != "" {
				t.Error("a refused delegation still reached the specialist")
			}
		})
	}
}

// TestSpecialistDenialIsPassedThrough checks that when the specialist refuses a
// call for want of scope, the coordinator sees that refusal rather than a
// broker error.
func TestSpecialistDenialIsPassedThrough(t *testing.T) {
	h := newHarness(t)
	h.specialistStatus = http.StatusForbidden
	h.specialistBody = `{"error":"insufficient_scope"}`

	resp := h.delegate(h.mintToken(wideScopes, time.Hour), map[string]any{
		"capability": "records.read",
	})

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if resp.Header.Get(HeaderDerivedScope) == "" {
		t.Error("the derived scope header was lost on a denied call")
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t)

	resp, err := h.broker.Client().Get(h.broker.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header  string
		want    string
		wantErr bool
	}{
		{"Bearer abc", "abc", false},
		{"bearer abc", "abc", false},
		{"BEARER abc", "abc", false},
		{"Basic abc", "", true},
		{"Bearer ", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		got, err := BearerToken(tt.header)
		if (err != nil) != tt.wantErr {
			t.Errorf("BearerToken(%q) error = %v, wantErr %v", tt.header, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("BearerToken(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestAudienceAcceptsBothForms(t *testing.T) {
	var single Audience
	if err := json.Unmarshal([]byte(`"one"`), &single); err != nil {
		t.Fatalf("unmarshal string aud: %v", err)
	}
	if len(single) != 1 || single[0] != "one" {
		t.Errorf("string aud parsed as %v", single)
	}

	var many Audience
	if err := json.Unmarshal([]byte(`["one","two"]`), &many); err != nil {
		t.Fatalf("unmarshal array aud: %v", err)
	}
	if len(many) != 2 {
		t.Errorf("array aud parsed as %v", many)
	}
}

// decodeClaims reads a token's payload without verifying it. Test helper only.
func decodeClaims(t *testing.T, token string) Claims {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}
