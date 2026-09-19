// Package derivation turns a delegation request into the narrowest set of
// OAuth2 scopes that request needs.
//
// It is deliberately free of framework and transport dependencies so it can be
// unit tested on its own and reused outside the broker. The policy format is
// JSON rather than YAML so the package needs nothing beyond the standard
// library.
package derivation

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// DefaultMaxDepth applies to a capability that does not set its own limit.
const DefaultMaxDepth = 3

// ScopeRule is one scope a capability may need, with an optional depth ceiling.
//
// A rule with MaxDepth 0 is unlimited within the capability's own ceiling. A
// rule with a positive MaxDepth drops out once the delegation has travelled
// that many hops, which is what makes the derivation a ratchet: going deeper
// can only ever remove scopes, never add them.
type ScopeRule struct {
	Name     string `json:"name"`
	MaxDepth int    `json:"maxDepth,omitempty"`
}

// UnmarshalJSON accepts either a bare string or a full object, so a policy
// author can write "records:read" when there is nothing to qualify.
func (r *ScopeRule) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, `"`) {
		var name string
		if err := json.Unmarshal(data, &name); err != nil {
			return err
		}
		r.Name = name
		r.MaxDepth = 0
		return nil
	}

	// Aliased to avoid recursing back into this method.
	type scopeRuleAlias ScopeRule
	var alias scopeRuleAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*r = ScopeRule(alias)
	return nil
}

// Capability is the minimum authority one named operation needs.
type Capability struct {
	Description string      `json:"description,omitempty"`
	Scopes      []ScopeRule `json:"scopes"`
	MaxDepth    int         `json:"maxDepth,omitempty"`
}

// Policy is the static capability to scope map the broker ships with.
//
// It is intentionally static. Everything the derivation needs is either in the
// delegation request itself or in this file, so the broker needs no policy
// store, no task classifier and no network call to decide a scope.
type Policy struct {
	Version int `json:"version"`
	// Resource is the RFC 8707 resource indicator the narrowed token is bound
	// to. Thunder ignores the `audience` parameter for the issued access token,
	// so this is what actually sets the audience.
	Resource     string                `json:"resource"`
	MaxDepth     int                   `json:"maxDepth,omitempty"`
	Capabilities map[string]Capability `json:"capabilities"`
}

// ParsePolicy reads a policy from raw JSON and validates it.
func ParsePolicy(data []byte) (Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// LoadPolicy reads a policy from a file on disk.
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy %s: %w", path, err)
	}
	return ParsePolicy(data)
}

// Validate rejects a policy that could not narrow anything meaningfully.
func (p Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d, want 1", p.Version)
	}
	if strings.TrimSpace(p.Resource) == "" {
		return fmt.Errorf("policy resource must be set")
	}
	if len(p.Capabilities) == 0 {
		return fmt.Errorf("policy defines no capabilities")
	}
	for name, capability := range p.Capabilities {
		if len(capability.Scopes) == 0 {
			return fmt.Errorf("capability %q defines no scopes", name)
		}
		for i, rule := range capability.Scopes {
			if strings.TrimSpace(rule.Name) == "" {
				return fmt.Errorf("capability %q scope %d has an empty name", name, i)
			}
			if rule.MaxDepth < 0 {
				return fmt.Errorf("capability %q scope %q has a negative maxDepth", name, rule.Name)
			}
		}
		if capability.MaxDepth < 0 {
			return fmt.Errorf("capability %q has a negative maxDepth", name)
		}
	}
	return nil
}

// depthCeiling is the delegation depth beyond which a capability is refused
// outright.
func (p Policy) depthCeiling(c Capability) int {
	if c.MaxDepth > 0 {
		return c.MaxDepth
	}
	if p.MaxDepth > 0 {
		return p.MaxDepth
	}
	return DefaultMaxDepth
}
