package derivation

import (
	_ "embed"
	"sync"
)

//go:embed policy.json
var defaultPolicyJSON []byte

var (
	defaultOnce   sync.Once
	defaultPolicy Policy
	defaultErr    error
)

// DefaultPolicy returns the policy compiled into the binary. The broker uses it
// when POLICY_PATH is not set, so the demo runs with no extra files to place.
func DefaultPolicy() (Policy, error) {
	defaultOnce.Do(func() {
		defaultPolicy, defaultErr = ParsePolicy(defaultPolicyJSON)
	})
	return defaultPolicy, defaultErr
}
