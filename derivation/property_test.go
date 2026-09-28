package derivation

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

// Property based tests over randomly generated policies and delegation chains.
//
// The table tests in derive_test.go check hand picked cases, which is the right
// tool for asserting specific intended behaviour. These tests exist for a
// different reason. Two of the properties this package claims are universally
// quantified, so no finite table can support them.
//
//	P1  no derived scope set exceeds what the policy declares for that
//	    capability, nor what the subject token holds
//	P2  derivation is monotonic in depth, so deriving at depth d+1 always
//	    returns a subset of what depth d returned
//
// P2 is the property that stops a long delegation chain from quietly regaining
// authority it shed at an earlier hop, and it is the one worth attacking with
// generated input rather than examples.
//
// A refusal counts as the empty set. ErrDepthExceeded and ErrNoScopes both mean
// the caller gets no authority at all, so folding them to the empty set is the
// faithful reading and keeps the subset relation total.

const propertyCases = 500

// scopeAlphabet is deliberately small. A narrow alphabet makes collisions
// between a capability's declared scopes and the subject token's held scopes
// common, which is where the interesting cases live. A wide alphabet would
// mostly generate disjoint sets that derive to nothing.
var scopeAlphabet = []string{
	"records:read", "records:list", "records:write", "records:delete",
	"tickets:read", "tickets:write",
}

func TestPropertyDerivationNeverExceedsItsBounds(t *testing.T) {
	for seed := range propertyCases {
		policy, capNames := randomPolicy(uint64(seed))
		if err := policy.Validate(); err != nil {
			t.Fatalf("seed %d generated an invalid policy: %v", seed, err)
		}
		available := randomAvailable(uint64(seed))

		for _, name := range capNames {
			capability := policy.Capabilities[name]
			declared := declaredScopes(capability)
			ceiling := policy.depthCeiling(capability)

			for depth := 0; depth <= ceiling+1; depth++ {
				got := deriveOrEmpty(t, policy, name, depth, available)

				for _, s := range got {
					if !slices.Contains(declared, s) {
						t.Fatalf("seed %d capability %q depth %d: derived %q, which the policy never declares (declared %v)",
							seed, name, depth, s, declared)
					}
				}

				// An empty Available means the subject token carried no scope
				// claim, which the package treats as "do not intersect". The
				// intersection property only has meaning when the caller
				// actually told us what it holds.
				if len(available) == 0 {
					continue
				}
				for _, s := range got {
					if !slices.Contains(available, s) {
						t.Fatalf("seed %d capability %q depth %d: derived %q, which the subject token does not hold (holds %v)",
							seed, name, depth, s, available)
					}
				}
			}
		}
	}
}

func TestPropertyDerivationIsMonotonicInDepth(t *testing.T) {
	for seed := range propertyCases {
		policy, capNames := randomPolicy(uint64(seed))
		available := randomAvailable(uint64(seed))

		for _, name := range capNames {
			ceiling := policy.depthCeiling(policy.Capabilities[name])

			// One hop past the ceiling, so the transition into refusal is
			// covered rather than just the range that succeeds.
			previous := deriveOrEmpty(t, policy, name, 0, available)
			for depth := 1; depth <= ceiling+1; depth++ {
				current := deriveOrEmpty(t, policy, name, depth, available)

				for _, s := range current {
					if !slices.Contains(previous, s) {
						t.Fatalf("seed %d capability %q: depth %d derived %q which depth %d did not, so authority grew with depth (%v -> %v)",
							seed, name, depth, s, depth-1, previous, current)
					}
				}
				previous = current
			}
		}
	}
}

// deriveOrEmpty runs Derive and folds an expected refusal into the empty set.
// An unexpected error fails the test, so a new error kind cannot silently start
// being read as "no authority".
func deriveOrEmpty(t *testing.T, p Policy, capability string, depth int, available []string) []string {
	t.Helper()

	result, err := Derive(DelegationContext{
		Task:       "generated",
		Capability: capability,
		Depth:      depth,
		Available:  available,
	}, p)
	switch {
	case err == nil:
		return result.Scopes
	case errors.Is(err, ErrDepthExceeded), errors.Is(err, ErrNoScopes):
		return nil
	default:
		t.Fatalf("capability %q depth %d: unexpected error kind: %v", capability, depth, err)
		return nil
	}
}

// randomPolicy builds a valid policy from a seed. It returns the capability
// names sorted, so a failure reported against a seed is reproducible rather
// than depending on map iteration order.
func randomPolicy(seed uint64) (Policy, []string) {
	r := rand.New(rand.NewPCG(seed, 0x5eed))

	policy := Policy{
		Version:      1,
		Resource:     "https://generated.agentid.local",
		MaxDepth:     r.IntN(6), // 0 means fall back to DefaultMaxDepth
		Capabilities: map[string]Capability{},
	}

	for i := range 1 + r.IntN(5) {
		rules := make([]ScopeRule, 0, 6)
		for _, s := range pickScopes(r, 1+r.IntN(6)) {
			rules = append(rules, ScopeRule{
				Name: s,
				// 0 means unlimited within the capability's own ceiling.
				MaxDepth: r.IntN(5),
			})
		}
		policy.Capabilities[fmt.Sprintf("generated.cap%d", i)] = Capability{
			Scopes:   rules,
			MaxDepth: r.IntN(6),
		}
	}

	names := make([]string, 0, len(policy.Capabilities))
	for name := range policy.Capabilities {
		names = append(names, name)
	}
	slices.Sort(names)
	return policy, names
}

// randomAvailable stands in for the subject token's scope claim. It returns an
// empty set about one time in eight, so the no-scope-claim path is exercised
// too.
func randomAvailable(seed uint64) []string {
	r := rand.New(rand.NewPCG(seed, 0xa11ce))
	if r.IntN(8) == 0 {
		return nil
	}
	return pickScopes(r, 1+r.IntN(len(scopeAlphabet)))
}

// pickScopes draws n distinct scopes from the alphabet.
func pickScopes(r *rand.Rand, n int) []string {
	shuffled := slices.Clone(scopeAlphabet)
	r.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return sortedUnique(shuffled[:min(n, len(shuffled))])
}

func declaredScopes(c Capability) []string {
	names := make([]string, 0, len(c.Scopes))
	for _, rule := range c.Scopes {
		names = append(names, rule.Name)
	}
	return sortedUnique(names)
}

// TestEmptyAvailableSkipsIntersection documents, rather than endorses, what
// happens when the subject token carries no scope claim. Derive then keeps
// every scope the capability declares, because it has nothing to intersect
// against.
//
// Keeping everything is the right call for a library, which cannot tell an
// authority-free caller apart from one that simply did not supply its held
// scopes. It is the wrong call for a broker, where an absent scope claim is
// never ambiguous, so the broker guards the empty case itself and refuses the
// delegation with 403 rather than calling Derive.
//
// That guard is load bearing rather than defensive. ThunderID answers an
// over-requested exchange with 200 and no scope field at all, so a token
// carrying no authority whatsoever still verifies cleanly, and without the
// guard it would derive a capability's full declared set on its next hop.
func TestEmptyAvailableSkipsIntersection(t *testing.T) {
	policy := Policy{
		Version:  1,
		Resource: "https://generated.agentid.local",
		Capabilities: map[string]Capability{
			"records.read": {Scopes: []ScopeRule{{Name: "records:read"}, {Name: "records:list"}}},
		},
	}

	got := deriveOrEmpty(t, policy, "records.read", 0, nil)
	want := []string{"records:list", "records:read"}
	if !slices.Equal(got, want) {
		t.Fatalf("with no scope claim to intersect against, got %v, want %v", got, want)
	}
}
