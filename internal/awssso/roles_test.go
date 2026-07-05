package awssso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roleInfo mirrors the SSO ListAccountRoles wire shape under "roleList".
type roleInfo struct {
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
}

// mockRolesSSO stands in for the SSO portal's ListAccountRoles endpoint. It
// serves a configurable set of roles and counts the calls / records the bearer
// token and account so tests can assert on the request and on caching.
type mockRolesSSO struct {
	server *httptest.Server

	roles      []string
	calls      atomic.Int64
	gotToken   atomic.Value  // string
	gotAccount atomic.Value  // string
	block      chan struct{} // when non-nil, each handler blocks until closed
}

func newMockRolesSSO(t *testing.T, roles ...string) *mockRolesSSO {
	t.Helper()

	m := &mockRolesSSO{roles: roles}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.block != nil {
			<-m.block
		}

		account := r.URL.Query().Get("account_id")

		m.calls.Add(1)
		m.gotToken.Store(r.Header.Get("X-Amz-Sso_bearer_token"))
		m.gotAccount.Store(account)

		list := make([]roleInfo, 0, len(m.roles))
		for _, name := range m.roles {
			list = append(list, roleInfo{AccountID: account, RoleName: name})
		}

		body, err := json.Marshal(map[string][]roleInfo{"roleList": list})
		assert.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(m.server.Close)

	return m
}

func (m *mockRolesSSO) resolver(region, token string) *Roles {
	return NewRoles(region, token, nil, WithRolesClientFunc(func(region string) *sso.Client {
		return sso.New(sso.Options{
			Region:       region,
			BaseEndpoint: aws.String(m.server.URL),
			Credentials:  aws.AnonymousCredentials{},
		})
	}))
}

func TestRoles_SingleRoleResolves(t *testing.T) {
	t.Parallel()

	m := newMockRolesSSO(t, testRole)
	role, err := m.resolver(testRegion, testToken).Role(context.Background(), testAccount)
	require.NoError(t, err)

	assert.Equal(t, testRole, role)
	assert.Equal(t, testToken, m.gotToken.Load())
	gotAccount, _ := m.gotAccount.Load().(string)
	assert.Equal(t, testAccount, gotAccount)
}

func TestRoles_NoRolesIsError(t *testing.T) {
	t.Parallel()

	m := newMockRolesSSO(t) // no roles
	_, err := m.resolver(testRegion, testToken).Role(context.Background(), testAccount)
	require.Error(t, err)
	assert.Contains(t, err.Error(), testAccount)
}

func TestRoles_MultipleRolesIsError(t *testing.T) {
	t.Parallel()

	m := newMockRolesSSO(t, "ReadOnly", "Admin")
	_, err := m.resolver(testRegion, testToken).Role(context.Background(), testAccount)
	require.Error(t, err)

	// The error names the candidate roles so the operator can pick one.
	assert.Contains(t, err.Error(), "ReadOnly")
	assert.Contains(t, err.Error(), "Admin")
}

func TestRoles_SlowDiscoveryDoesNotBlockCachedAccount(t *testing.T) {
	t.Parallel()

	const otherAccount = "999999999999"

	m := newMockRolesSSO(t, testRole)
	resolver := m.resolver(testRegion, testToken)

	// Resolve (and cache) one account while the mock still serves freely.
	_, err := resolver.Role(context.Background(), testAccount)
	require.NoError(t, err)

	// Now make every discovery block, and start a discovery for a different,
	// uncached account — it parks inside ListAccountRoles holding no lock.
	m.block = make(chan struct{})

	discovering := make(chan struct{})
	go func() {
		close(discovering)
		_, _ = resolver.Role(context.Background(), otherAccount)
	}()
	<-discovering

	// The blocked discovery must not hold the mutex: a cache hit for the
	// already-resolved account has to return promptly, not wait behind it.
	done := make(chan string, 1)
	go func() {
		role, roleErr := resolver.Role(context.Background(), testAccount)
		require.NoError(t, roleErr)
		done <- role
	}()

	select {
	case role := <-done:
		assert.Equal(t, testRole, role)
	case <-time.After(2 * time.Second):
		t.Fatal("a cache hit blocked behind an in-flight discovery for another account")
	}

	close(m.block) // release the parked discovery
}

func TestRoles_CachesResolvedRole(t *testing.T) {
	t.Parallel()

	m := newMockRolesSSO(t, testRole)
	resolver := m.resolver(testRegion, testToken)

	first, err := resolver.Role(context.Background(), testAccount)
	require.NoError(t, err)

	second, err := resolver.Role(context.Background(), testAccount)
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.Equal(t, int64(1), m.calls.Load(), "a cached role must not re-call ListAccountRoles")
}
