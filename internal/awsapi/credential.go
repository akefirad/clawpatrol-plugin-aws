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
// ADR 0001 D3 models the per-account allowlist as repeated `account { … }`
// blocks. The pluginsdk v0.5.3 schema (register.go ctyTypeFromString) only
// accepts flat attributes of primitive / list-of-primitive types — nested
// object blocks are not expressible — so this first cut carries a single
// account as flat attributes (id / role_name / placeholder). Expanding to the
// repeated-block allowlist is deferred until the SDK grows a block schema
// (tracked with the allowlist slice); the login wiring below is unaffected.
type ssoConfig struct {
	StartURL    string `json:"start_url"`
	Region      string `json:"region"`
	AccountID   string `json:"account_id"`
	RoleName    string `json:"role_name"`
	Placeholder string `json:"placeholder"`
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
			{Name: "account_id", TypeString: "string", Required: true},
			{Name: "role_name", TypeString: "string"},
			{Name: "placeholder", TypeString: "string"},
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

	if cfg.AccountID == "" {
		return nil, errors.New("aws_sso: account_id is required")
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
