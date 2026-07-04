package awssso

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/pluginsdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingDialer is a fake gateway dial: it records every (addr, opts) it is
// asked to broker, then connects each call straight to a local plaintext HTTP
// responder. The gateway terminates upstream TLS and hands the plugin a
// plaintext pipe, so the brokered client wires this as its DialTLSContext — a
// plaintext local server is exactly what a real brokered dial yields.
type recordingDialer struct {
	target string // host:port of the local mock SSO responder

	mu    sync.Mutex
	addrs []string
	opts  []*pluginsdk.DialUpstreamOptions
}

func (d *recordingDialer) dial(ctx context.Context, network, addr string, opts *pluginsdk.DialUpstreamOptions) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.opts = append(d.opts, opts)
	d.mu.Unlock()

	var dialer net.Dialer

	return dialer.DialContext(ctx, network, d.target)
}

// assertBrokered fails unless the SSO client opened its first (only) connection
// through the brokered dial, targeting host:443 with gateway-terminated TLS. It
// fails when the SDK used its default (direct) transport — the dialer records
// nothing then.
func (d *recordingDialer) assertBrokered(t *testing.T, host string) {
	t.Helper()

	d.mu.Lock()
	defer d.mu.Unlock()

	require.NotEmpty(t, d.addrs, "the SSO client must dial through the brokered gateway dial, not a default transport")
	assert.Equal(t, host+":443", d.addrs[0], "the brokered dial must target the SSO portal host on 443")

	require.NotNil(t, d.opts[0])
	assert.True(t, d.opts[0].TLS, "the gateway must be asked to terminate upstream TLS")
	assert.Equal(t, host, d.opts[0].TLSServerName, "the SNI/verification name must be the SSO portal host")
}

// TestMinter_ProductionClientBrokersGetRoleCredentials exercises the production
// client construction (no WithClientFunc override — the client is built exactly
// as it is in the gateway) with only the dial faked, and proves
// sso:GetRoleCredentials routes through the brokered dial. It fails if the SSO
// client uses the SDK's default transport (regression guard for #16).
func TestMinter_ProductionClientBrokersGetRoleCredentials(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	mock := newMockSSO(t, expiresIn(time.Hour))
	dialer := &recordingDialer{target: mock.server.Listener.Addr().String()}

	minter := New(testRegion, testToken, time.Minute, dialer.dial)

	creds, err := minter.Credentials(context.Background(), testAccount, testRole)
	must.NoError(err)
	is.Equal(mintedAKID, creds.AccessKeyID)

	// The mint reached the mock SSO responder over the brokered pipe, carrying
	// the delivered token — proof the request rode the fake dial, not a socket.
	is.Equal(int64(1), mock.mintCount())
	is.Equal(testToken, mock.lastToken())

	dialer.assertBrokered(t, "portal.sso."+testRegion+".amazonaws.com")
}

// TestRoles_ProductionClientBrokersListAccountRoles is the companion regression
// guard for sso:ListAccountRoles: production client construction, only the dial
// faked, and the call must route through the brokered dial.
func TestRoles_ProductionClientBrokersListAccountRoles(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	mock := newMockRolesSSO(t, testRole)
	dialer := &recordingDialer{target: mock.server.Listener.Addr().String()}

	resolver := NewRoles(testRegion, testToken, dialer.dial)

	role, err := resolver.Role(context.Background(), testAccount)
	must.NoError(err)
	is.Equal(testRole, role)

	dialer.assertBrokered(t, "portal.sso."+testRegion+".amazonaws.com")
}
