// Package awssso mints short-lived AWS credentials for a single configured
// role via sso:GetRoleCredentials, using the SSO access token the gateway
// delivers as Conn.CredentialSecret, and caches them per (account, role).
//
// Each (account, role) is served by an aws.CredentialsCache wrapping a
// provider that calls GetRoleCredentials: retrieval is lazy, refresh happens
// only inside the configured ExpiryWindow, and a concurrent burst collapses
// to a single mint (the cache single-flights). The caches are in-memory and
// scoped to one Minter, so a process restart starts cold and repopulates from
// the re-delivered token — no re-login.
package awssso

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
)

// ssoClientFunc builds an SSO client for a region. It is the overridable
// sso-client seam: production defaults it to a brokered client (built from the
// gateway dial threaded into New), tests point it at a mock server.
type ssoClientFunc func(region string) *sso.Client

// cacheKey identifies one credential cache: temporary credentials are minted
// and cached per target account and role.
type cacheKey struct {
	account string
	role    string
}

// Minter mints and caches temporary role credentials for one SSO session. It
// holds the SSO access token (delivered as Conn.CredentialSecret) and a cache
// per (account, role). Safe for concurrent use.
type Minter struct {
	region       string
	token        string
	expiryWindow time.Duration
	newClient    ssoClientFunc

	mu     sync.Mutex
	caches map[cacheKey]*aws.CredentialsCache
}

// Option customizes a Minter at construction.
type Option func(*Minter)

// WithClientFunc overrides the sso-client seam — the way a Minter builds its
// SSO client. Production leaves it defaulted to the brokered client; tests pass
// a factory pointed at a mock server.
func WithClientFunc(fn ssoClientFunc) Option {
	return func(m *Minter) { m.newClient = fn }
}

// New builds a Minter for the SSO region and access token, with expiryWindow
// as the refresh margin applied to every cached credential. dial is the
// gateway's brokered dial (pluginsdk.Conn.DialUpstream): the SSO client routes
// every sso:GetRoleCredentials call through it, since the plugin has no network
// of its own (ADR 0001 Capabilities).
func New(region, token string, expiryWindow time.Duration, dial DialFunc, opts ...Option) *Minter {
	m := &Minter{
		region:       region,
		token:        token,
		expiryWindow: expiryWindow,
		newClient:    func(r string) *sso.Client { return newSSOClient(r, dial) },
		caches:       make(map[cacheKey]*aws.CredentialsCache),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Credentials returns temporary credentials for the account and role, minting
// via sso:GetRoleCredentials on a cold or expired cache and serving the cached
// value otherwise.
func (m *Minter) Credentials(ctx context.Context, account, role string) (aws.Credentials, error) {
	cache := m.cacheFor(account, role)

	creds, err := cache.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("mint credentials for %s/%s: %w", account, role, err)
	}

	return creds, nil
}

// cacheFor returns the credential cache for (account, role), creating it on
// first use.
func (m *Minter) cacheFor(account, role string) *aws.CredentialsCache {
	key := cacheKey{account: account, role: role}

	m.mu.Lock()
	defer m.mu.Unlock()

	if cache, ok := m.caches[key]; ok {
		return cache
	}

	provider := &roleProvider{
		newClient: m.newClient,
		region:    m.region,
		token:     m.token,
		account:   account,
		role:      role,
	}
	cache := aws.NewCredentialsCache(provider, func(o *aws.CredentialsCacheOptions) {
		o.ExpiryWindow = m.expiryWindow
	})
	m.caches[key] = cache

	return cache
}

// roleProvider is the aws.CredentialsProvider that mints one role's
// credentials via sso:GetRoleCredentials. The enclosing aws.CredentialsCache
// owns caching, the expiry window, and single-flight refresh.
type roleProvider struct {
	newClient ssoClientFunc
	region    string
	token     string
	account   string
	role      string
}

// Retrieve mints fresh credentials from the SSO portal.
func (p *roleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	client := p.newClient(p.region)

	out, err := client.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: aws.String(p.token),
		AccountId:   aws.String(p.account),
		RoleName:    aws.String(p.role),
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("sso GetRoleCredentials: %w", err)
	}

	rc := out.RoleCredentials
	if rc == nil {
		return aws.Credentials{}, errors.New("sso GetRoleCredentials: empty role credentials")
	}

	// Guard a zero/negative expiration rather than caching a permanently
	// expired entry (Expiration is epoch milliseconds).
	if rc.Expiration <= 0 {
		return aws.Credentials{}, fmt.Errorf("sso GetRoleCredentials: non-positive expiration %d", rc.Expiration)
	}

	return aws.Credentials{
		AccessKeyID:     aws.ToString(rc.AccessKeyId),
		SecretAccessKey: aws.ToString(rc.SecretAccessKey),
		SessionToken:    aws.ToString(rc.SessionToken),
		Source:          "aws_sso GetRoleCredentials",
		AccountID:       p.account,
		CanExpire:       true,
		Expires:         time.UnixMilli(rc.Expiration),
	}, nil
}
