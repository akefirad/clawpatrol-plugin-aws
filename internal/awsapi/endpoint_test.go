package awsapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/denoland/clawpatrol/pluginsdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akefirad/clawpatrol-plugin-aws/internal/awssso"
)

// The agent signs with the account's placeholder identity (ADR 0001 D5); the
// endpoint decodes the account from it, mints real SSO credentials for the
// auto-discovered role, and re-signs with the minted identity.
const (
	testPlaceholderAKID = "AKIA1234567890120000" // AKIA + account(123456789012) + padding
	testAccount         = "123456789012"
	testRole            = "ReadOnly"
	testSSORegion       = "eu-central-1"
	testSSOToken        = "sso-access-token-xyz" // delivered as Conn.CredentialSecret
	testHost            = "sts.us-east-1.amazonaws.com"
	testBody            = `{"Action":"GetCallerIdentity","Version":"2011-06-15"}`

	mintedAKID  = "ASIAMINTEDCREDS00001"
	mintedToken = "minted-session-token"
)

// allowlist builds the fail-closed account allowlist handleConn dispatches on.
func allowlist(accounts ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(accounts))
	for _, a := range accounts {
		set[a] = struct{}{}
	}

	return set
}

// fakeResolver is a roleResolver stub: it returns a fixed role and counts the
// lookups so a denied request can prove no role was ever resolved.
type fakeResolver struct {
	role  string
	calls int
}

func (r *fakeResolver) Role(_ context.Context, _ string) (string, error) {
	r.calls++
	return r.role, nil
}

// fakeMinter is a roleMinter stub recording its calls so a denied request can
// prove no credentials were minted.
type fakeMinter struct {
	calls int
}

func (m *fakeMinter) Credentials(_ context.Context, _, _ string) (aws.Credentials, error) {
	m.calls++
	return aws.Credentials{AccessKeyID: "SHOULD-NOT-BE-USED"}, nil
}

// fakeUpstream is the net.Conn returned by the fake DialUpstream: it captures
// everything the handler writes (the re-signed request) and serves a canned
// HTTP response back.
type fakeUpstream struct {
	written  bytes.Buffer
	response io.Reader
}

func (u *fakeUpstream) Read(p []byte) (int, error)  { return u.response.Read(p) }
func (u *fakeUpstream) Write(p []byte) (int, error) { return u.written.Write(p) }
func (u *fakeUpstream) Close() error                { return nil }
func (u *fakeUpstream) LocalAddr() net.Addr         { return nil }
func (u *fakeUpstream) RemoteAddr() net.Addr        { return nil }
func (u *fakeUpstream) SetDeadline(time.Time) error {
	return nil
}
func (u *fakeUpstream) SetReadDeadline(time.Time) error  { return nil }
func (u *fakeUpstream) SetWriteDeadline(time.Time) error { return nil }

// fakeConn is a minimal gatewayConn: it feeds one incoming request, captures
// the response written back to the agent, records the Evaluate call, and hands
// out a fakeUpstream from DialUpstream.
type fakeConn struct {
	incoming io.Reader
	toAgent  bytes.Buffer

	evalCalls   int
	evalFacet   string
	evalAction  map[string]any
	evalSummary string
	verdict     pluginsdk.Verdict

	dialAddr string
	upstream *fakeUpstream
}

func (c *fakeConn) Read(p []byte) (int, error)  { return c.incoming.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error) { return c.toAgent.Write(p) }

func (c *fakeConn) Evaluate(_ context.Context, facet string, action map[string]any, summary string) (pluginsdk.Verdict, error) {
	c.evalCalls++
	c.evalFacet = facet
	c.evalAction = action
	c.evalSummary = summary

	return c.verdict, nil
}

func (c *fakeConn) DialUpstream(_ context.Context, _, addr string, _ *pluginsdk.DialUpstreamOptions) (net.Conn, error) {
	c.dialAddr = addr
	return c.upstream, nil
}

func rawRequest(akid string) string {
	return fmt.Sprintf(
		"POST / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Authorization: AWS4-HMAC-SHA256 Credential=%s/20200101/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=deadbeef\r\n"+
			"X-Amz-Security-Token: PLACEHOLDER-TOKEN\r\n"+
			"Content-Type: application/x-amz-json-1.0\r\n"+
			"Content-Length: %d\r\n"+
			"\r\n%s",
		testHost, akid, len(testBody), testBody,
	)
}

// rawRequestNoAuth is a request with no SigV4 Authorization header — i.e. an
// agent with no matching placeholder profile. Dispatch must fail closed.
func rawRequestNoAuth() string {
	return fmt.Sprintf(
		"POST / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-amz-json-1.0\r\n"+
			"Content-Length: %d\r\n"+
			"\r\n%s",
		testHost, len(testBody), testBody,
	)
}

// mockSSOServer stands in for the SSO portal's GetRoleCredentials endpoint,
// recording the bearer token it was called with so the test can prove minting
// used the token delivered as CredentialSecret.
type mockSSOServer struct {
	server   *httptest.Server
	seenAuth string
}

func newMockSSOServer(t *testing.T) *mockSSOServer {
	t.Helper()

	m := &mockSSOServer{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.seenAuth = r.Header.Get("X-Amz-Sso_bearer_token")

		resp := fmt.Sprintf(
			`{"roleCredentials":{"accessKeyId":%q,"secretAccessKey":%q,"sessionToken":%q,"expiration":%d}}`,
			mintedAKID, "minted-secret-access-key", mintedToken, time.Now().Add(time.Hour).UnixMilli(),
		)

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, resp)
	}))
	t.Cleanup(m.server.Close)

	return m
}

func (m *mockSSOServer) minter() *awssso.Minter {
	return awssso.New(testSSORegion, testSSOToken, time.Minute, awssso.WithClientFunc(func(region string) *sso.Client {
		return sso.New(sso.Options{
			Region:       region,
			BaseEndpoint: aws.String(m.server.URL),
			Credentials:  aws.AnonymousCredentials{},
		})
	}))
}

func TestHandleConn_AllowedAccountMintsAndReSigns(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	mock := newMockSSOServer(t)
	upstream := &fakeUpstream{
		response: bytes.NewReader([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")),
	}
	conn := &fakeConn{
		incoming: bytes.NewReader([]byte(rawRequest(testPlaceholderAKID))),
		verdict:  pluginsdk.Verdict{Action: "allow"},
		upstream: upstream,
	}
	resolver := &fakeResolver{role: testRole}

	err := handleConn(context.Background(), conn, allowlist(testAccount), mock.minter(), resolver)
	must.NoError(err)

	// The account on the allowlist resolved its role and proceeded.
	is.Equal(1, resolver.calls)

	// Evaluate ran against the minimal aws facet, account decoded from the AKID.
	is.Equal(FacetName, conn.evalFacet)
	must.NotNil(conn.evalAction)
	is.Equal(testAccount, conn.evalAction["account"])
	is.Equal("sts", conn.evalAction["service"])
	is.Equal("us-east-1", conn.evalAction["region"])
	is.Equal(http.MethodPost, conn.evalAction["method"])
	is.Equal("/", conn.evalAction["resource"])

	// Brokered dial targeted the AWS host.
	is.Equal(testHost+":443", conn.dialAddr)

	// The outbound request carries the SSO-minted identity, not the placeholder.
	out, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(upstream.written.Bytes())))
	must.NoError(err)

	authz := out.Header.Get("Authorization")
	is.Contains(authz, "Credential="+mintedAKID+"/")
	is.NotContains(authz, testPlaceholderAKID)
	is.Equal(mintedToken, out.Header.Get("X-Amz-Security-Token"))

	// Minting used the SSO access token delivered as CredentialSecret.
	is.Equal(testSSOToken, mock.seenAuth)

	// The upstream body is preserved through the re-sign.
	body, err := io.ReadAll(out.Body)
	must.NoError(err)
	is.JSONEq(testBody, string(body))
}

// denied asserts a fail-closed outcome: a 403 to the agent, and no role
// resolution, no mint, and no upstream dial.
func denied(t *testing.T, conn *fakeConn, minter *fakeMinter, resolver *fakeResolver) {
	t.Helper()

	is := assert.New(t)
	must := require.New(t)

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(conn.toAgent.Bytes())), nil)
	must.NoError(err)

	defer func() { _ = resp.Body.Close() }()

	is.Equal(http.StatusForbidden, resp.StatusCode)

	is.Equal(0, resolver.calls, "denied request must not resolve a role")
	is.Equal(0, minter.calls, "denied request must not mint credentials")
	is.Empty(conn.dialAddr, "denied request must not dial upstream")
}

func TestHandleConn_UnknownAccountDenied(t *testing.T) {
	t.Parallel()

	conn := &fakeConn{
		incoming: bytes.NewReader([]byte(rawRequest(testPlaceholderAKID))),
		verdict:  pluginsdk.Verdict{Action: "allow"}, // even an allow verdict must not save it
	}
	minter := &fakeMinter{}
	resolver := &fakeResolver{role: testRole}

	// testAccount is not on the allowlist.
	err := handleConn(context.Background(), conn, allowlist("999999999999"), minter, resolver)
	require.NoError(t, err)

	denied(t, conn, minter, resolver)
}

func TestHandleConn_NoAKIDDenied(t *testing.T) {
	t.Parallel()

	conn := &fakeConn{
		incoming: bytes.NewReader([]byte(rawRequestNoAuth())),
		verdict:  pluginsdk.Verdict{Action: "allow"},
	}
	minter := &fakeMinter{}
	resolver := &fakeResolver{role: testRole}

	err := handleConn(context.Background(), conn, allowlist(testAccount), minter, resolver)
	require.NoError(t, err)

	denied(t, conn, minter, resolver)
}

func TestEndpointParams_ReadsAllowlistAndTokenFromSecret(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	cfg, err := json.Marshal(ssoConfig{
		Region:   testSSORegion,
		Accounts: []string{testAccount, "999999999999"},
	})
	must.NoError(err)

	region, token, accounts, err := endpointParams(cfg, []byte(testSSOToken))
	must.NoError(err)

	is.Equal(testSSORegion, region)
	is.Equal(testSSOToken, token)
	is.Equal([]string{testAccount, "999999999999"}, accounts)
}
