package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pasindubalasooriya/agentid-scope-broker/derivation"
)

// RFC 8693 constants.
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
)

var (
	// ErrExchangeRejected means Thunder refused to issue a token.
	ErrExchangeRejected = errors.New("token exchange rejected")

	// ErrScopeNotHonoured means Thunder issued a token, but with fewer scopes
	// than were asked for.
	//
	// This is the failure mode worth guarding hardest against. Thunder drops
	// scopes outside the permitted intersection silently and still returns 200,
	// so without this check a narrowing that quietly lost a scope looks exactly
	// like one that worked.
	ErrScopeNotHonoured = errors.New("issued scope does not match the requested scope")
)

// ExchangedToken is a successfully narrowed token.
type ExchangedToken struct {
	AccessToken string
	TokenType   string
	Scopes      []string
	ExpiresIn   int
	IssuedType  string
}

// ThunderClient performs RFC 8693 token exchange against ThunderID.
type ThunderClient struct {
	tokenEndpoint string
	clientID      string
	clientSecret  string
	client        *http.Client
}

// NewThunderClient builds a client for one Thunder token endpoint.
func NewThunderClient(tokenEndpoint, clientID, clientSecret string, timeout time.Duration) *ThunderClient {
	return &ThunderClient{
		tokenEndpoint: tokenEndpoint,
		clientID:      clientID,
		clientSecret:  clientSecret,
		client:        &http.Client{Timeout: timeout},
	}
}

// Exchange swaps a subject token for one carrying exactly the requested scopes.
//
// The `resource` parameter is RFC 8707 and is what actually binds the issued
// token's audience. Thunder accepts `audience` for RFC 8693 compatibility but
// ignores it when setting `aud`, so it is not sent here.
func (t *ThunderClient) Exchange(ctx context.Context, subjectToken string, want derivation.Result) (ExchangedToken, error) {
	if len(want.Scopes) == 0 {
		return ExchangedToken{}, fmt.Errorf("refusing to exchange for an empty scope set")
	}

	form := url.Values{
		"grant_type":         {GrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {TokenTypeAccessToken},
		"scope":              {strings.Join(want.Scopes, " ")},
	}
	if want.Resource != "" {
		form.Set("resource", want.Resource)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ExchangedToken{}, fmt.Errorf("build exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(t.clientID, t.clientSecret)

	resp, err := t.client.Do(req)
	if err != nil {
		return ExchangedToken{}, fmt.Errorf("%w: %w", ErrExchangeRejected, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ExchangedToken{}, fmt.Errorf("%w: read response: %w", ErrExchangeRejected, err)
	}

	if resp.StatusCode != http.StatusOK {
		return ExchangedToken{}, fmt.Errorf("%w: %s: %s", ErrExchangeRejected, resp.Status, oauthError(body))
	}

	var payload struct {
		AccessToken     string `json:"access_token"`
		TokenType       string `json:"token_type"`
		Scope           string `json:"scope"`
		ExpiresIn       int    `json:"expires_in"`
		IssuedTokenType string `json:"issued_token_type"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ExchangedToken{}, fmt.Errorf("%w: decode response: %w", ErrExchangeRejected, err)
	}
	if payload.AccessToken == "" {
		return ExchangedToken{}, fmt.Errorf("%w: response carried no access_token", ErrExchangeRejected)
	}

	issued := derivation.ParseScopeClaim(payload.Scope)
	if missing := missingScopes(want.Scopes, issued); len(missing) > 0 {
		return ExchangedToken{}, fmt.Errorf("%w: asked for [%s], got [%s], missing [%s]",
			ErrScopeNotHonoured,
			strings.Join(want.Scopes, " "),
			strings.Join(issued, " "),
			strings.Join(missing, " "))
	}

	return ExchangedToken{
		AccessToken: payload.AccessToken,
		TokenType:   payload.TokenType,
		Scopes:      issued,
		ExpiresIn:   payload.ExpiresIn,
		IssuedType:  payload.IssuedTokenType,
	}, nil
}

// missingScopes returns the requested scopes that the issued set does not hold.
func missingScopes(requested, issued []string) []string {
	var missing []string
	for _, s := range requested {
		if !slices.Contains(issued, s) {
			missing = append(missing, s)
		}
	}
	return missing
}

// oauthError pulls the RFC 6749 error fields out of an error response so a
// failure says something useful in the logs.
func oauthError(body []byte) string {
	var payload struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Error != "" {
		if payload.Description != "" {
			return payload.Error + ": " + payload.Description
		}
		return payload.Error
	}
	text := strings.TrimSpace(string(body))
	if len(text) > 300 {
		text = text[:300] + "..."
	}
	if text == "" {
		return "no response body"
	}
	return text
}
