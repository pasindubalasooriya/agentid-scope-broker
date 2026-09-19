package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pasindubalasooriya/agentid-scope-broker/derivation"
)

// Config is the broker's whole runtime configuration. Everything comes from the
// environment so the same binary runs locally and in the cluster.
type Config struct {
	// Addr is the listen address, for example ":8081".
	Addr string

	// ThunderBaseURL is the ThunderID issuer base, for example
	// http://thunder.amp.localhost:8080
	ThunderBaseURL string

	// ThunderIssuer is the expected `iss` claim on subject tokens. It defaults
	// to ThunderBaseURL, which is what a default local install uses.
	ThunderIssuer string

	// BrokerClientID and BrokerClientSecret authenticate the broker at the
	// token endpoint. This client must have the token-exchange grant in its
	// registered grantTypes, because Thunder checks the grant against the
	// client authenticating at the endpoint.
	BrokerClientID     string
	BrokerClientSecret string

	// SpecialistURL is the base URL of the specialist agent.
	SpecialistURL string

	// PolicyPath overrides the policy compiled into the binary.
	PolicyPath string

	// OTLPEndpoint and AgentAPIKey configure trace export into Agent Manager's
	// collector. Tracing is skipped when OTLPEndpoint is empty.
	OTLPEndpoint string
	AgentAPIKey  string

	// ServiceName is the service.name resource attribute on exported spans.
	ServiceName string

	// ForwardTimeout bounds the call to the specialist.
	ForwardTimeout time.Duration

	// ThunderTimeout bounds the token exchange call.
	ThunderTimeout time.Duration
}

// LoadConfig reads configuration from the environment and validates it.
func LoadConfig() (Config, derivation.Policy, error) {
	c := Config{
		Addr:               envOr("BROKER_ADDR", ":8081"),
		ThunderBaseURL:     strings.TrimRight(os.Getenv("THUNDER_BASE_URL"), "/"),
		ThunderIssuer:      strings.TrimRight(os.Getenv("THUNDER_ISSUER"), "/"),
		BrokerClientID:     os.Getenv("BROKER_CLIENT_ID"),
		BrokerClientSecret: os.Getenv("BROKER_CLIENT_SECRET"),
		SpecialistURL:      strings.TrimRight(os.Getenv("SPECIALIST_URL"), "/"),
		PolicyPath:         os.Getenv("POLICY_PATH"),
		// AMP_OTEL_ENDPOINT is what Agent Manager injects into its agents, so
		// accept it as well as the standard OTel variable. That way one setting
		// configures the broker and both agents.
		OTLPEndpoint: strings.TrimRight(
			firstNonEmpty(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), os.Getenv("AMP_OTEL_ENDPOINT")), "/"),
		AgentAPIKey: os.Getenv("AMP_AGENT_API_KEY"),
		ServiceName: envOr("OTEL_SERVICE_NAME", "agentid-scope-broker"),
	}

	if c.ThunderIssuer == "" {
		c.ThunderIssuer = c.ThunderBaseURL
	}

	var err error
	if c.ForwardTimeout, err = envDuration("FORWARD_TIMEOUT", 30*time.Second); err != nil {
		return Config{}, derivation.Policy{}, err
	}
	if c.ThunderTimeout, err = envDuration("THUNDER_TIMEOUT", 10*time.Second); err != nil {
		return Config{}, derivation.Policy{}, err
	}

	for name, value := range map[string]string{
		"THUNDER_BASE_URL":     c.ThunderBaseURL,
		"BROKER_CLIENT_ID":     c.BrokerClientID,
		"BROKER_CLIENT_SECRET": c.BrokerClientSecret,
		"SPECIALIST_URL":       c.SpecialistURL,
	} {
		if value == "" {
			return Config{}, derivation.Policy{}, fmt.Errorf("%s must be set", name)
		}
	}

	policy, err := loadPolicy(c.PolicyPath)
	if err != nil {
		return Config{}, derivation.Policy{}, err
	}

	return c, policy, nil
}

func loadPolicy(path string) (derivation.Policy, error) {
	if path == "" {
		return derivation.DefaultPolicy()
	}
	return derivation.LoadPolicy(path)
}

// TokenEndpoint is where both the exchange and any client credentials call go.
func (c Config) TokenEndpoint() string { return c.ThunderBaseURL + "/oauth2/token" }

// JWKSEndpoint is where subject token signing keys come from.
func (c Config) JWKSEndpoint() string { return c.ThunderBaseURL + "/oauth2/jwks" }

// firstNonEmpty returns the first value that is not blank.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d, nil
	}
	// Accept a bare number of seconds as well, which is what most of the
	// surrounding deployment configuration uses.
	secs, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a duration: %q", name, raw)
	}
	return time.Duration(secs) * time.Second, nil
}
