package derivation

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Errors returned by Derive. The broker maps these onto HTTP status codes, so
// they are part of the package's contract.
var (
	// ErrUnknownCapability means the delegation named a capability the policy
	// does not describe. Derivation fails closed rather than falling back to
	// the subject token's own authority.
	ErrUnknownCapability = errors.New("unknown capability")

	// ErrDepthExceeded means the delegation has travelled more hops than the
	// capability permits.
	ErrDepthExceeded = errors.New("delegation depth exceeded")

	// ErrNoScopes means nothing survived narrowing, usually because the subject
	// token never held the scopes the capability needs.
	ErrNoScopes = errors.New("no scopes remain after derivation")

	// ErrNegativeDepth means the caller supplied a malformed depth.
	ErrNegativeDepth = errors.New("delegation depth must not be negative")
)

// DelegationContext is everything the derivation is allowed to see. It comes
// entirely from the incoming delegation request and the verified subject token,
// with no outside lookup.
type DelegationContext struct {
	// Task is a free text description of what the caller is delegating. It is
	// carried for traceability and is not used to widen the result.
	Task string

	// Capability is the named operation being invoked, for example
	// "records.read". This is the key the policy is keyed on.
	Capability string

	// Depth is how many delegation hops have already happened. A direct call
	// from the coordinator is depth 0.
	Depth int

	// Available is the scope set the verified subject token actually holds. The
	// derived set is intersected with it so the broker never asks Thunder for
	// more authority than the caller was given.
	Available []string
}

// Result is a derived scope set plus enough detail to explain the decision in a
// trace or a log line.
type Result struct {
	// Scopes is the narrowed set, sorted and deduplicated.
	Scopes []string

	// Resource is the RFC 8707 resource indicator to bind the token to.
	Resource string

	// Dropped lists scopes the capability asked for that did not survive, with
	// a short reason each. This is what makes an unexpectedly narrow result
	// debuggable instead of mysterious.
	Dropped []DroppedScope
}

// DroppedScope records one scope that the policy wanted but the derivation
// removed.
type DroppedScope struct {
	Name   string
	Reason string
}

// Reasons a scope can be dropped.
const (
	ReasonDepth       = "beyond scope depth limit"
	ReasonUnavailable = "not held by the subject token"
)

// String renders the scope set the way an OAuth2 request wants it.
func (r Result) String() string {
	return strings.Join(r.Scopes, " ")
}

// Derive works out the narrowest scope set that satisfies one delegation.
//
// The result is monotonic in Depth: for the same capability and the same
// available scopes, deriving at a greater depth can only ever return a subset
// of what a shallower depth returns. That property is what stops a long
// delegation chain from quietly regaining authority it shed earlier.
func Derive(ctx DelegationContext, p Policy) (Result, error) {
	if ctx.Depth < 0 {
		return Result{}, fmt.Errorf("%w: got %d", ErrNegativeDepth, ctx.Depth)
	}

	name := strings.TrimSpace(ctx.Capability)
	capability, ok := p.Capabilities[name]
	if !ok {
		return Result{}, fmt.Errorf("%w: %q", ErrUnknownCapability, ctx.Capability)
	}

	ceiling := p.depthCeiling(capability)
	if ctx.Depth >= ceiling {
		return Result{}, fmt.Errorf("%w: capability %q allows %d hops, got depth %d",
			ErrDepthExceeded, name, ceiling, ctx.Depth)
	}

	available := newScopeSet(ctx.Available)
	intersect := len(ctx.Available) > 0

	var (
		kept    []string
		dropped []DroppedScope
	)
	for _, rule := range capability.Scopes {
		if rule.MaxDepth > 0 && ctx.Depth >= rule.MaxDepth {
			dropped = append(dropped, DroppedScope{Name: rule.Name, Reason: ReasonDepth})
			continue
		}
		if intersect {
			if _, held := available[rule.Name]; !held {
				dropped = append(dropped, DroppedScope{Name: rule.Name, Reason: ReasonUnavailable})
				continue
			}
		}
		kept = append(kept, rule.Name)
	}

	kept = sortedUnique(kept)
	if len(kept) == 0 {
		return Result{}, fmt.Errorf("%w: capability %q at depth %d", ErrNoScopes, name, ctx.Depth)
	}

	return Result{Scopes: kept, Resource: p.Resource, Dropped: dropped}, nil
}

func newScopeSet(scopes []string) map[string]struct{} {
	set := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = struct{}{}
		}
	}
	return set
}

func sortedUnique(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}
	out := slices.Clone(scopes)
	slices.Sort(out)
	return slices.Compact(out)
}

// ParseScopeClaim splits the space delimited `scope` claim or token response
// field into a set of scopes.
func ParseScopeClaim(scope string) []string {
	return sortedUnique(strings.Fields(scope))
}
