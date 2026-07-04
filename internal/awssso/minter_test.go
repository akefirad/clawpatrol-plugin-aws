package awssso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRegion  = "eu-central-1"
	testToken   = "sso-access-token-abc"
	testAccount = "123456789012"
	testRole    = "ReadOnly"

	mintedAKID   = "ASIAMINTEDCREDS00001"
	mintedSecret = "minted-secret-access-key"
	mintedToken  = "minted-session-token"
)

// roleCreds is the shape the SSO GetRoleCredentials wire response wraps under
// the "roleCredentials" key. Expiration is epoch milliseconds.
type roleCreds struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	Expiration      int64  `json:"expiration"`
}

// mockSSO is an httptest server standing in for the SSO portal's
// GetRoleCredentials endpoint. It counts the mint calls and records the last
// bearer token / query it saw so tests can assert the token came from the
// caller and that caching suppressed extra calls.
type mockSSO struct {
	server *httptest.Server

	mints       atomic.Int64
	gotToken    atomic.Value // string
	gotAccount  atomic.Value // string
	gotRole     atomic.Value // string
	expiration  int64
	releaseMint chan struct{} // when non-nil, each handler blocks until closed
}

func newMockSSO(t *testing.T, expiration int64) *mockSSO {
	t.Helper()

	m := &mockSSO{expiration: expiration}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.releaseMint != nil {
			<-m.releaseMint
		}

		m.mints.Add(1)
		m.gotToken.Store(r.Header.Get("X-Amz-Sso_bearer_token"))
		m.gotAccount.Store(r.URL.Query().Get("account_id"))
		m.gotRole.Store(r.URL.Query().Get("role_name"))

		body, err := json.Marshal(map[string]roleCreds{
			"roleCredentials": {
				AccessKeyID:     mintedAKID,
				SecretAccessKey: mintedSecret,
				SessionToken:    mintedToken,
				Expiration:      m.expiration,
			},
		})
		assert.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(m.server.Close)

	return m
}

func (m *mockSSO) mintCount() int64 { return m.mints.Load() }

func (m *mockSSO) lastToken() string {
	v, _ := m.gotToken.Load().(string)
	return v
}

// mint builds a Minter whose sso-client seam points at the mock server, so
// tests exercise the real GetRoleCredentials request/response path without
// racing on shared package state.
func (m *mockSSO) mint(region, token string, window time.Duration) *Minter {
	return New(region, token, window, WithClientFunc(func(region string) *sso.Client {
		return sso.New(sso.Options{
			Region:       region,
			BaseEndpoint: aws.String(m.server.URL),
			Credentials:  aws.AnonymousCredentials{},
		})
	}))
}

// expiresIn returns an epoch-millisecond expiration `d` from now.
func expiresIn(d time.Duration) int64 {
	return time.Now().Add(d).UnixMilli()
}

func TestMinter_MintsFromSSOToken(t *testing.T) {
	t.Parallel()

	m := newMockSSO(t, expiresIn(time.Hour))
	minter := m.mint(testRegion, testToken, time.Minute)

	creds, err := minter.Credentials(context.Background(), testAccount, testRole)
	require.NoError(t, err)

	assert.Equal(t, mintedAKID, creds.AccessKeyID)
	assert.Equal(t, mintedSecret, creds.SecretAccessKey)
	assert.Equal(t, mintedToken, creds.SessionToken)
	assert.True(t, creds.CanExpire)

	assert.Equal(t, int64(1), m.mintCount())
	// The mint used the SSO token delivered to the minter, plus the requested
	// account/role.
	assert.Equal(t, testToken, m.lastToken())

	gotAccount, _ := m.gotAccount.Load().(string)
	assert.Equal(t, testAccount, gotAccount)

	gotRole, _ := m.gotRole.Load().(string)
	assert.Equal(t, testRole, gotRole)
}

func TestMinter_CacheHitSkipsSecondMint(t *testing.T) {
	t.Parallel()

	m := newMockSSO(t, expiresIn(time.Hour))
	minter := m.mint(testRegion, testToken, time.Minute)

	first, err := minter.Credentials(context.Background(), testAccount, testRole)
	require.NoError(t, err)

	second, err := minter.Credentials(context.Background(), testAccount, testRole)
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.Equal(t, int64(1), m.mintCount(), "cached credentials should not re-mint")
}

func TestMinter_RefreshesWithinExpiryWindow(t *testing.T) {
	t.Parallel()

	// Credentials expire in 30s but the window is 60s, so they read as expired
	// on retrieval and every call re-mints.
	m := newMockSSO(t, expiresIn(30*time.Second))
	minter := m.mint(testRegion, testToken, time.Minute)

	_, err := minter.Credentials(context.Background(), testAccount, testRole)
	require.NoError(t, err)

	_, err = minter.Credentials(context.Background(), testAccount, testRole)
	require.NoError(t, err)

	assert.Equal(t, int64(2), m.mintCount(), "creds inside the expiry window should re-mint")
}

func TestMinter_SingleFlightUnderConcurrentBurst(t *testing.T) {
	t.Parallel()

	m := newMockSSO(t, expiresIn(time.Hour))
	m.releaseMint = make(chan struct{})
	minter := m.mint(testRegion, testToken, time.Minute)

	const burst = 20

	var (
		wg    sync.WaitGroup
		errCh = make(chan error, burst)
	)

	for range burst {
		wg.Go(func() {
			_, err := minter.Credentials(context.Background(), testAccount, testRole)
			errCh <- err
		})
	}

	// Let the burst pile up on a single in-flight mint, then release it.
	time.Sleep(50 * time.Millisecond)
	close(m.releaseMint)

	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}

	assert.Equal(t, int64(1), m.mintCount(), "a concurrent burst must trigger exactly one mint")
}

func TestMinter_RejectsNonPositiveExpiration(t *testing.T) {
	t.Parallel()

	for _, exp := range []int64{0, -1000} {
		m := newMockSSO(t, exp)
		minter := m.mint(testRegion, testToken, time.Minute)

		_, err := minter.Credentials(context.Background(), testAccount, testRole)
		require.Error(t, err, "expiration %d must be rejected", exp)
	}
}

func TestMinter_RestartRepopulatesFromToken(t *testing.T) {
	t.Parallel()

	m := newMockSSO(t, expiresIn(time.Hour))
	first := m.mint(testRegion, testToken, time.Minute)

	_, err := first.Credentials(context.Background(), testAccount, testRole)
	require.NoError(t, err)
	assert.Equal(t, int64(1), m.mintCount())

	// A restart drops the in-memory cache; a fresh minter carrying the
	// re-delivered token mints again with no re-login.
	second := m.mint(testRegion, testToken, time.Minute)

	creds, err := second.Credentials(context.Background(), testAccount, testRole)
	require.NoError(t, err)

	assert.Equal(t, mintedAKID, creds.AccessKeyID)
	assert.Equal(t, int64(2), m.mintCount(), "a fresh cache re-mints from the token")
}
