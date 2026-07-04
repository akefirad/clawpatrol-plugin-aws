package awssso

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
)

// Roles auto-discovers the single role for an account via sso:ListAccountRoles
// (ADR 0001 D3), using the SSO access token the gateway delivers as
// Conn.CredentialSecret. Discovery must resolve to exactly one role per account
// (else a clear error naming the candidates), and the resolved role is cached
// per account so a repeat lookup does not re-call the portal. Auto-discovery
// only ever narrows within the account boundary — the account allowlist itself
// is never discovered (ADR 0001 D4). Safe for concurrent use.
type Roles struct {
	region    string
	token     string
	newClient ssoClientFunc

	mu    sync.Mutex
	cache map[string]string // account -> resolved role
}

// RolesOption customizes a Roles resolver at construction.
type RolesOption func(*Roles)

// WithRolesClientFunc overrides the sso-client seam — the way a resolver builds
// its SSO client. Production leaves it defaulted to newSSOClient; tests pass a
// factory pointed at a mock server.
func WithRolesClientFunc(fn ssoClientFunc) RolesOption {
	return func(r *Roles) { r.newClient = fn }
}

// NewRoles builds a role resolver for the SSO region and access token.
func NewRoles(region, token string, opts ...RolesOption) *Roles {
	r := &Roles{
		region:    region,
		token:     token,
		newClient: newSSOClient,
		cache:     make(map[string]string),
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Role returns the single auto-discovered role for the account, serving the
// cached value after the first lookup. Zero or multiple roles are a clear
// error; the multiple-roles error names the candidates.
func (r *Roles) Role(ctx context.Context, account string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if role, ok := r.cache[account]; ok {
		return role, nil
	}

	role, err := r.discover(ctx, account)
	if err != nil {
		return "", err
	}

	r.cache[account] = role

	return role, nil
}

// discover lists every role the SSO session grants on the account (following
// pagination) and enforces the single-role rule.
func (r *Roles) discover(ctx context.Context, account string) (string, error) {
	client := r.newClient(r.region)

	var (
		roles []string
		next  *string
	)

	for {
		out, err := client.ListAccountRoles(ctx, &sso.ListAccountRolesInput{
			AccessToken: aws.String(r.token),
			AccountId:   aws.String(account),
			NextToken:   next,
		})
		if err != nil {
			return "", fmt.Errorf("sso ListAccountRoles for account %s: %w", account, err)
		}

		for _, ri := range out.RoleList {
			roles = append(roles, aws.ToString(ri.RoleName))
		}

		if aws.ToString(out.NextToken) == "" {
			break
		}

		next = out.NextToken
	}

	switch len(roles) {
	case 1:
		return roles[0], nil
	case 0:
		return "", fmt.Errorf("aws_sso: account %s grants no roles for this SSO session", account)
	default:
		return "", fmt.Errorf(
			"aws_sso: account %s grants multiple roles (%s); a single role per account is required",
			account, strings.Join(roles, ", "),
		)
	}
}
