package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Subject token verification, written against the standard library only so the
// broker's trust decisions are all visible in one readable file.

var (
	// ErrNoToken means the request carried no bearer token.
	ErrNoToken = errors.New("no bearer token")
	// ErrInvalidToken covers every reason a token failed verification.
	ErrInvalidToken = errors.New("invalid token")
)

// kidPattern mirrors the constraint Agent Manager applies before using a `kid`
// in a lookup, so a malformed header cannot drive arbitrary cache churn.
var kidPattern = regexp.MustCompile(`^[a-zA-Z0-9._:=+/~-]{1,256}$`)

// Claims is the part of a ThunderID access token the broker cares about.
type Claims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience Audience `json:"aud"`
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	Scope    string   `json:"scope"`
	ClientID string   `json:"client_id"`
	// SubType is "agent" or "application" on tokens where Thunder was
	// configured to emit it. It is advisory, so a missing value is not an error.
	SubType string `json:"sub_type"`
}

// Scopes splits the space delimited scope claim.
func (c Claims) Scopes() []string { return strings.Fields(c.Scope) }

// Audience handles `aud` arriving as either a string or an array of strings.
type Audience []string

func (a *Audience) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var list []string
		if err := json.Unmarshal(data, &list); err != nil {
			return err
		}
		*a = list
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*a = []string{single}
	return nil
}

// Verifier checks RS256 tokens against a cached copy of Thunder's JWKS.
type Verifier struct {
	jwksURL string
	issuer  string
	client  *http.Client
	ttl     time.Duration

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	refreshLock sync.Mutex
}

// NewVerifier builds a verifier for one Thunder instance.
func NewVerifier(jwksURL, issuer string, client *http.Client) *Verifier {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{
		jwksURL: jwksURL,
		issuer:  issuer,
		client:  client,
		ttl:     time.Hour,
		keys:    map[string]*rsa.PublicKey{},
	}
}

// Verify parses and validates a token, returning its claims.
//
// It checks the RS256 signature against Thunder's published keys, the issuer,
// and expiry. It deliberately does not check the audience: the broker accepts a
// token issued for any resource and it is the callee that decides whether the
// audience suits it.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: expected 3 segments, got %d", ErrInvalidToken, len(parts))
	}

	headerJSON, err := decodeSegment(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: header: %w", ErrInvalidToken, err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Claims{}, fmt.Errorf("%w: header: %w", ErrInvalidToken, err)
	}
	if header.Alg != "RS256" {
		return Claims{}, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidToken, header.Alg)
	}
	if !kidPattern.MatchString(header.Kid) {
		return Claims{}, fmt.Errorf("%w: malformed kid", ErrInvalidToken)
	}

	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return Claims{}, err
	}

	signature, err := decodeSegment(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: signature: %w", ErrInvalidToken, err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return Claims{}, fmt.Errorf("%w: signature does not verify", ErrInvalidToken)
	}

	payloadJSON, err := decodeSegment(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: payload: %w", ErrInvalidToken, err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return Claims{}, fmt.Errorf("%w: payload: %w", ErrInvalidToken, err)
	}

	if v.issuer != "" && claims.Issuer != v.issuer {
		return Claims{}, fmt.Errorf("%w: issuer %q is not %q", ErrInvalidToken, claims.Issuer, v.issuer)
	}
	if claims.Expiry > 0 && time.Now().After(time.Unix(claims.Expiry, 0)) {
		return Claims{}, fmt.Errorf("%w: expired at %s", ErrInvalidToken, time.Unix(claims.Expiry, 0).UTC())
	}

	return claims, nil
}

// key returns the signing key for a kid, refreshing the cache once if the kid
// is unknown. Thunder rotates keys, so an unknown kid is an expected event
// rather than an error.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	fresh := time.Since(v.fetchedAt) < v.ttl
	v.mu.RUnlock()

	if ok && fresh {
		return key, nil
	}

	if err := v.refresh(ctx); err != nil {
		if ok {
			// The cache is stale but we still hold a key for this kid. Using it
			// beats failing the delegation outright.
			return key, nil
		}
		return nil, err
	}

	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: no signing key for kid %q", ErrInvalidToken, kid)
	}
	return key, nil
}

// Refresh fetches the JWKS immediately. Used at startup as a readiness check.
func (v *Verifier) Refresh(ctx context.Context) error { return v.refresh(ctx) }

func (v *Verifier) refresh(ctx context.Context) error {
	// One refresh at a time. A burst of unknown kids should cause one fetch.
	v.refreshLock.Lock()
	defer v.refreshLock.Unlock()

	v.mu.RLock()
	fetchedAt := v.fetchedAt
	v.mu.RUnlock()
	if time.Since(fetchedAt) < 30*time.Second {
		// Another goroutine just refreshed. Do not hammer Thunder.
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("build jwks request: %w", err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: %s returned %s", v.jwksURL, resp.Status)
	}

	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Alg != "" && k.Alg != "RS256") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pub, err := rsaPublicKey(k.N, k.E)
		if err != nil {
			// One unusable key should not invalidate the rest of the set.
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("jwks at %s contained no usable RS256 keys", v.jwksURL)
	}

	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

func rsaPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := decodeSegment(nB64)
	if err != nil {
		return nil, fmt.Errorf("modulus: %w", err)
	}
	eBytes, err := decodeSegment(eB64)
	if err != nil {
		return nil, fmt.Errorf("exponent: %w", err)
	}
	if len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, fmt.Errorf("exponent has an implausible length %d", len(eBytes))
	}

	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e <= 0 {
		return nil, fmt.Errorf("non positive exponent")
	}

	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// decodeSegment decodes unpadded base64url, which is what JWT and JWK use.
func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// BearerToken pulls the raw token out of an Authorization header.
func BearerToken(header string) (string, error) {
	const prefix = "bearer "
	if header == "" {
		return "", ErrNoToken
	}
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", fmt.Errorf("%w: expected a Bearer credential", ErrNoToken)
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", ErrNoToken
	}
	return token, nil
}
