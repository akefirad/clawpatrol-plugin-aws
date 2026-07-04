// Package awsapi implements the AWS SSO plugin's building blocks: the aws_sso
// credential (Connect-card wiring, no login code), the aws_api endpoint (SigV4
// re-sign + brokered proxy), and the minimal aws facet.
package awsapi

import (
	"errors"
	"fmt"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// CredentialTypeName is the HCL credential type this plugin registers.
const CredentialTypeName = "aws_sso"

// ssoConfig is the decoded aws_sso credential body.
//
// ADR 0001 D3: the per-account allowlist is a flat `accounts = list(string)`
// of 12-digit account ids. The pluginsdk v0.5.3 schema (register.go
// ctyTypeFromString) only accepts flat attributes of primitive /
// list-of-primitive types — nested `account { … }` blocks are not
// expressible — so the per-account role guard and placeholder override are
// deferred (option B): roles are auto-discovered and placeholders are derived.
type ssoConfig struct {
	StartURL string   `json:"start_url"`
	Region   string   `json:"region"`
	Accounts []string `json:"accounts"`
}

// Credential declares the aws_sso credential type.
//
// It carries no login code (ADR 0001 D9, Path A): the OAuthIntegration below
// wires the dashboard Connect card to the gateway core's ssooidc device flow
// (Flow == "aws_sso"). The gateway runs the flow, persists the token, and
// delivers it to the plugin's endpoint as Conn.CredentialSecret.
func Credential() pluginsdk.CredentialDef {
	return pluginsdk.CredentialDef{
		TypeName:       CredentialTypeName,
		Disambiguators: []string{"placeholder"},
		Schema: pluginsdk.Schema{Fields: []pluginsdk.SchemaField{
			{Name: "start_url", TypeString: "string", Required: true},
			{Name: "region", TypeString: "string", Required: true},
			{Name: "accounts", TypeString: "list(string)", Required: true},
		}},
		Build: buildCredential,
	}
}

func buildCredential(req pluginsdk.BuildRequest) (any, error) {
	var cfg ssoConfig
	if err := req.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode aws_sso config: %w", err)
	}

	if cfg.StartURL == "" {
		return nil, errors.New("aws_sso: start_url is required")
	}

	if cfg.Region == "" {
		return nil, errors.New("aws_sso: region is required")
	}

	if err := validateAccounts(cfg.Accounts); err != nil {
		return nil, err
	}

	return pluginsdk.CredentialBuildResult{
		Canonical: cfg,
		Metadata: pluginsdk.CredentialMetadata{
			// Renders the dashboard Connect card and routes login to the
			// gateway core's aws_sso device flow. AuthURL is the SSO start
			// URL the operator verifies; DeviceURL carries the SSO region.
			OAuth: &pluginsdk.OAuthIntegration{
				Flow: "aws_sso",
				OAuth: pluginsdk.OAuthConfig{
					AuthURL:   cfg.StartURL,
					DeviceURL: cfg.Region,
				},
			},
		},
	}, nil
}

// validateAccounts enforces the allowlist invariants (ADR 0001 D3/D4): a
// non-empty list of 12-digit account ids, each appearing at most once.
func validateAccounts(accounts []string) error {
	if len(accounts) == 0 {
		return errors.New("aws_sso: accounts is required and must list at least one account id")
	}

	seen := make(map[string]struct{}, len(accounts))
	for _, id := range accounts {
		if !isAccountID(id) {
			return fmt.Errorf("aws_sso: account %q is not a 12-digit account id", id)
		}

		if _, dup := seen[id]; dup {
			return fmt.Errorf("aws_sso: duplicate account %q in accounts", id)
		}

		seen[id] = struct{}{}
	}

	return nil
}

// isAccountID reports whether s is exactly 12 decimal digits.
func isAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}

	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}
