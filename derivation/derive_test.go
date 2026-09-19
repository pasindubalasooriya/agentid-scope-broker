package derivation_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/pasindubalasooriya/agentid-scope-broker/derivation"
)

// wideScopes is what the coordinator agent holds in the baseline: everything
// the specialist resource server defines.
var wideScopes = []string{
	"records:read",
	"records:list",
	"records:write",
}

func testPolicy(t *testing.T) derivation.Policy {
	t.Helper()
	p, err := derivation.DefaultPolicy()
	if err != nil {
		t.Fatalf("DefaultPolicy: %v", err)
	}
	return p
}

func TestDerive(t *testing.T) {
	p := testPolicy(t)

	tests := []struct {
		name    string
		ctx     derivation.DelegationContext
		want    []string
		wantErr error
	}{
		{
			name: "read task narrows away write authority",
			ctx: derivation.DelegationContext{
				Task:       "fetch record 42 for the support ticket",
				Capability: "records.read",
				Depth:      0,
				Available:  wideScopes,
			},
			want: []string{"records:list", "records:read"},
		},
		{
			name: "summarise needs read only, not list",
			ctx: derivation.DelegationContext{
				Capability: "records.summarise",
				Depth:      0,
				Available:  wideScopes,
			},
			want: []string{"records:read"},
		},
		{
			name: "write task does not pick up read authority",
			ctx: derivation.DelegationContext{
				Capability: "records.write",
				Depth:      0,
				Available:  wideScopes,
			},
			want: []string{"records:write"},
		},
		{
			name: "one hop deeper drops the depth limited scope",
			ctx: derivation.DelegationContext{
				Capability: "records.read",
				Depth:      1,
				Available:  wideScopes,
			},
			want: []string{"records:read"},
		},
		{
			name: "result is capped by what the subject token holds",
			ctx: derivation.DelegationContext{
				Capability: "records.read",
				Depth:      0,
				Available:  []string{"records:read"},
			},
			want: []string{"records:read"},
		},
		{
			name: "empty available means no intersection is applied",
			ctx: derivation.DelegationContext{
				Capability: "records.summarise",
				Depth:      0,
			},
			want: []string{"records:read"},
		},
		{
			name: "unknown capability fails closed",
			ctx: derivation.DelegationContext{
				Capability: "records.delete",
				Depth:      0,
				Available:  wideScopes,
			},
			wantErr: derivation.ErrUnknownCapability,
		},
		{
			name: "write is refused once it has been delegated onward",
			ctx: derivation.DelegationContext{
				Capability: "records.write",
				Depth:      1,
				Available:  wideScopes,
			},
			wantErr: derivation.ErrDepthExceeded,
		},
		{
			name: "policy ceiling refuses an over long chain",
			ctx: derivation.DelegationContext{
				Capability: "records.read",
				Depth:      3,
				Available:  wideScopes,
			},
			wantErr: derivation.ErrDepthExceeded,
		},
		{
			name: "subject token without the needed scope yields nothing",
			ctx: derivation.DelegationContext{
				Capability: "records.write",
				Depth:      0,
				Available:  []string{"records:read"},
			},
			wantErr: derivation.ErrNoScopes,
		},
		{
			name: "negative depth is rejected",
			ctx: derivation.DelegationContext{
				Capability: "records.read",
				Depth:      -1,
				Available:  wideScopes,
			},
			wantErr: derivation.ErrNegativeDepth,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := derivation.Derive(tt.ctx, p)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Derive error = %v, want %v", err, tt.wantErr)
				}
				if len(got.Scopes) != 0 {
					t.Errorf("Derive returned scopes %v alongside an error", got.Scopes)
				}
				return
			}

			if err != nil {
				t.Fatalf("Derive: unexpected error %v", err)
			}
			if !slices.Equal(got.Scopes, tt.want) {
				t.Errorf("Derive scopes = %v, want %v", got.Scopes, tt.want)
			}
			if got.Resource != p.Resource {
				t.Errorf("Derive resource = %q, want %q", got.Resource, p.Resource)
			}
		})
	}
}

// TestDeriveNarrowsTheBaseline is the claim the whole project rests on: for a
// read task, the derived set is strictly smaller than the coordinator's own
// standing authority.
func TestDeriveNarrowsTheBaseline(t *testing.T) {
	p := testPolicy(t)

	got, err := derivation.Derive(derivation.DelegationContext{
		Capability: "records.summarise",
		Depth:      0,
		Available:  wideScopes,
	}, p)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	if len(got.Scopes) >= len(wideScopes) {
		t.Fatalf("derived %d scopes from a baseline of %d, expected strictly fewer",
			len(got.Scopes), len(wideScopes))
	}
	for _, s := range got.Scopes {
		if !slices.Contains(wideScopes, s) {
			t.Errorf("derived scope %q was not held by the subject token", s)
		}
	}
	if slices.Contains(got.Scopes, "records:write") {
		t.Error("a read only task derived write authority")
	}
}

// TestDepthIsMonotonic checks the ratchet property directly: going one hop
// deeper never adds a scope back.
func TestDepthIsMonotonic(t *testing.T) {
	p := testPolicy(t)

	for capability := range p.Capabilities {
		t.Run(capability, func(t *testing.T) {
			var previous []string
			havePrevious := false

			for depth := range 6 {
				got, err := derivation.Derive(derivation.DelegationContext{
					Capability: capability,
					Depth:      depth,
					Available:  wideScopes,
				}, p)
				if err != nil {
					// Once a depth is refused, deeper ones stay refused, which
					// trivially preserves the property.
					break
				}

				if havePrevious {
					for _, s := range got.Scopes {
						if !slices.Contains(previous, s) {
							t.Fatalf("depth %d added scope %q that depth %d did not grant",
								depth, s, depth-1)
						}
					}
				}
				previous = got.Scopes
				havePrevious = true
			}
		})
	}
}

func TestParseScopeClaim(t *testing.T) {
	got := derivation.ParseScopeClaim("  b:2   a:1  b:2 ")
	want := []string{"a:1", "b:2"}
	if !slices.Equal(got, want) {
		t.Errorf("ParseScopeClaim = %v, want %v", got, want)
	}
	if got := derivation.ParseScopeClaim(""); got != nil {
		t.Errorf("ParseScopeClaim(\"\") = %v, want nil", got)
	}
}

func TestPolicyValidation(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"wrong version", `{"version":2,"resource":"r","capabilities":{"a":{"scopes":["s"]}}}`},
		{"no resource", `{"version":1,"capabilities":{"a":{"scopes":["s"]}}}`},
		{"no capabilities", `{"version":1,"resource":"r","capabilities":{}}`},
		{"capability without scopes", `{"version":1,"resource":"r","capabilities":{"a":{"scopes":[]}}}`},
		{"empty scope name", `{"version":1,"resource":"r","capabilities":{"a":{"scopes":["  "]}}}`},
		{"negative scope depth", `{"version":1,"resource":"r","capabilities":{"a":{"scopes":[{"name":"s","maxDepth":-1}]}}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := derivation.ParsePolicy([]byte(tt.json)); err == nil {
				t.Error("ParsePolicy accepted an invalid policy")
			}
		})
	}
}

func TestScopeRuleAcceptsBothForms(t *testing.T) {
	p, err := derivation.ParsePolicy([]byte(
		`{"version":1,"resource":"r","capabilities":{"a":{"scopes":["plain",{"name":"qualified","maxDepth":2}]}}}`))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}

	scopes := p.Capabilities["a"].Scopes
	if len(scopes) != 2 {
		t.Fatalf("got %d scopes, want 2", len(scopes))
	}
	if scopes[0].Name != "plain" || scopes[0].MaxDepth != 0 {
		t.Errorf("string form parsed as %+v", scopes[0])
	}
	if scopes[1].Name != "qualified" || scopes[1].MaxDepth != 2 {
		t.Errorf("object form parsed as %+v", scopes[1])
	}
}
