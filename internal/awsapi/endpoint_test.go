package awsapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	testCredInstance    = "prod-aws"             // the aws_sso credential instance name
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

	resultCalls  int
	result       map[string]any
	resultErr    error // returned by SetResult to exercise the best-effort path
	resultSample []byte

	emitCalls int
	emitEvent pluginsdk.ConnEvent
}

// Emit records the supplementary audit events the handler emits (e.g. the
// denied-for-reauth marker, ADR 0001 D13) so tests can assert on them.
func (c *fakeConn) Emit(ev pluginsdk.ConnEvent) {
	c.emitCalls++
	c.emitEvent = ev
}

func (c *fakeConn) Read(p []byte) (int, error)  { return c.incoming.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error) { return c.toAgent.Write(p) }

// SetResult records the reported outcome. When the result carries a
// response_body stream it drains it (as the gateway would) into resultSample so
// tests can assert the teed sample.
func (c *fakeConn) SetResult(_ context.Context, result map[string]any) error {
	c.resultCalls++
	c.result = result

	if sv, ok := result[resultFieldResponseBody].(pluginsdk.StreamValue); ok {
		c.resultSample, _ = io.ReadAll(sv.R)
	}

	return c.resultErr
}

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
	return awssso.New(testSSORegion, testSSOToken, time.Minute, nil, awssso.WithClientFunc(func(region string) *sso.Client {
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
		verdict:  pluginsdk.Verdict{Action: verdictAllow},
		upstream: upstream,
	}
	resolver := &fakeResolver{role: testRole}

	err := handleConn(context.Background(), conn, allowlist(testAccount), mock.minter(), resolver, testCredInstance, true)
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

	// The verb is unknowable for this JSON-1.0 body (no X-Amz-Target, no Action
	// param), so action falls back to "METHOD path" and iam_action is omitted.
	is.Equal("POST /", conn.evalAction["action"])
	is.NotContains(conn.evalAction, "iam_action")

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

// awsChunkedBody frames payload as a single aws-chunked data chunk followed by
// the terminating zero chunk — the wire shape an S3 streaming upload sends.
func awsChunkedBody(payload []byte) string {
	const sig = ";chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n"

	return fmt.Sprintf("%x", len(payload)) + sig + string(payload) + "\r\n" + "0" + sig + "\r\n"
}

// rawChunkedPut builds an S3 PutObject request sent aws-chunked with
// Expect: 100-continue — the shape that fails SignatureDoesNotMatch unless the
// gateway decodes the body and drops the chunk-framing headers before
// re-signing.
func rawChunkedPut(host, akid string, payload []byte) string {
	framed := awsChunkedBody(payload)

	return fmt.Sprintf(
		"PUT /bucket/key.txt HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Authorization: AWS4-HMAC-SHA256 Credential=%s/20200101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=deadbeef\r\n"+
			"X-Amz-Security-Token: PLACEHOLDER-TOKEN\r\n"+
			"Content-Encoding: aws-chunked\r\n"+
			"X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n"+
			"X-Amz-Decoded-Content-Length: %d\r\n"+
			"X-Amz-Checksum-Crc32c: aXQ9Cw==\r\n"+
			"Expect: 100-continue\r\n"+
			"Content-Length: %d\r\n"+
			"\r\n%s",
		host, akid, len(payload), len(framed), framed,
	)
}

func TestHandleConn_S3PutObjectChunkedReSigns(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	const s3Host = "s3.us-east-1.amazonaws.com"

	payload := []byte("the-object-bytes-payload")

	mock := newMockSSOServer(t)
	upstream := &fakeUpstream{
		response: bytes.NewReader([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")),
	}
	conn := &fakeConn{
		incoming: bytes.NewReader([]byte(rawChunkedPut(s3Host, testPlaceholderAKID, payload))),
		verdict:  pluginsdk.Verdict{Action: verdictAllow},
		upstream: upstream,
	}
	resolver := &fakeResolver{role: testRole}

	err := handleConn(context.Background(), conn, allowlist(testAccount), mock.minter(), resolver, testCredInstance, true)
	must.NoError(err)

	// The enriched facet reached Evaluate with the reconstructed S3 op.
	must.NotNil(conn.evalAction)
	is.Equal("s3", conn.evalAction["service"])
	is.Equal("PutObject", conn.evalAction["action"])
	is.Equal("s3:PutObject", conn.evalAction["iam_action"])
	is.Equal(http.MethodPut, conn.evalAction["method"])
	is.Equal("/bucket/key.txt", conn.evalAction["resource"])

	// Expect: 100-continue was acknowledged so the agent streamed the body.
	is.Contains(conn.toAgent.String(), "100 Continue")

	// The outbound request carries the decoded raw payload, not the framing.
	out, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(upstream.written.Bytes())))
	must.NoError(err)

	body, err := io.ReadAll(out.Body)
	must.NoError(err)
	is.Equal(payload, body)
	is.Equal(int64(len(payload)), out.ContentLength)

	// The chunk-framing / checksum headers the re-sign can't reproduce are gone,
	// and X-Amz-Content-Sha256 is the hash of the raw payload (not STREAMING-*).
	is.Empty(out.Header.Get("Content-Encoding"))
	is.Empty(out.Header.Get("X-Amz-Decoded-Content-Length"))
	is.Empty(out.Header.Get("X-Amz-Checksum-Crc32c"))

	sum := sha256.Sum256(payload)
	is.Equal(hex.EncodeToString(sum[:]), out.Header.Get("X-Amz-Content-Sha256"))

	// Signed with the minted identity.
	is.Contains(out.Header.Get("Authorization"), "Credential="+mintedAKID+"/")
	is.Equal(mintedToken, out.Header.Get("X-Amz-Security-Token"))
}

// TestHandleConn_HITLAllowProceeds proves the synchronous HITL path: a
// hitl_allow verdict (the gateway held the connection through the approve chain
// and a human approved) proceeds exactly like a plain allow — role resolved,
// credentials minted fresh after the verdict (ADR 0001 request flow), re-signed,
// and dialed upstream.
func TestHandleConn_HITLAllowProceeds(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	mock := newMockSSOServer(t)
	upstream := &fakeUpstream{
		response: bytes.NewReader([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")),
	}
	conn := &fakeConn{
		incoming: bytes.NewReader([]byte(rawRequest(testPlaceholderAKID))),
		verdict:  pluginsdk.Verdict{Action: verdictHITLAllow},
		upstream: upstream,
	}
	resolver := &fakeResolver{role: testRole}

	err := handleConn(context.Background(), conn, allowlist(testAccount), mock.minter(), resolver, testCredInstance, true)
	must.NoError(err)

	// The approved request resolved its role, minted fresh, and dialed upstream.
	is.Equal(1, resolver.calls, "hitl_allow must resolve the role")
	is.Equal(testHost+":443", conn.dialAddr, "hitl_allow must dial upstream")

	// Minted after the verdict, with the SSO token delivered as CredentialSecret.
	is.Equal(testSSOToken, mock.seenAuth)

	// The outbound request carries the minted identity, not the placeholder.
	out, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(upstream.written.Bytes())))
	must.NoError(err)
	is.Contains(out.Header.Get("Authorization"), "Credential="+mintedAKID+"/")
	is.Equal(mintedToken, out.Header.Get("X-Amz-Security-Token"))
}

// TestHandleConn_DenyVerdictsBlock proves deny and hitl_deny both block with no
// SSO work: no role resolution, no mint, no upstream dial, and a 403 to the
// agent (ADR 0001: mint happens only after an allowing verdict).
func TestHandleConn_DenyVerdictsBlock(t *testing.T) {
	t.Parallel()

	for _, action := range []string{verdictDeny, verdictHITLDeny} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()

			conn := &fakeConn{
				incoming: bytes.NewReader([]byte(rawRequest(testPlaceholderAKID))),
				verdict:  pluginsdk.Verdict{Action: action, Reason: "policy: " + action},
			}
			minter := &fakeMinter{}
			resolver := &fakeResolver{role: testRole}

			err := handleConn(context.Background(), conn, allowlist(testAccount), minter, resolver, testCredInstance, true)
			require.NoError(t, err)

			// The account is on the allowlist, so it was evaluated — but the
			// verdict blocked it before any SSO work.
			assert.Equal(t, 1, conn.evalCalls, "a blocked request is still evaluated")
			denied(t, conn, minter, resolver)
		})
	}
}

// TestHandleConn_ExpiredSessionSurfacesReauth proves ADR 0001 D13: when the
// gateway delivers no live SSO token (an empty CredentialSecret, session expired
// with no refresh), a well-formed on-allowlist request that would otherwise be
// served is denied with a recognizable re-auth error naming the credential — not
// a mint attempt, not a dial, and no token/secret material in the response.
func TestHandleConn_ExpiredSessionSurfacesReauth(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	conn := &fakeConn{
		incoming: bytes.NewReader([]byte(rawRequest(testPlaceholderAKID))),
		verdict:  pluginsdk.Verdict{Action: verdictAllow}, // would otherwise be served
	}
	minter := &fakeMinter{}
	resolver := &fakeResolver{role: testRole}

	// hasToken=false models the empty CredentialSecret the gateway delivers on an
	// expired session.
	err := handleConn(context.Background(), conn, allowlist(testAccount), minter, resolver, testCredInstance, false)
	must.NoError(err)

	// Denied with a recognizable re-auth error naming the credential — no SSO work.
	status, body := agentResponse(t, conn)
	is.Equal(http.StatusForbidden, status)
	is.Contains(string(body), "AWS SSO session expired")
	is.Contains(string(body), testCredInstance)
	is.Contains(string(body), "dashboard")

	// No token or credential material leaks into the response.
	is.NotContains(string(body), testSSOToken)

	// The doomed request never resolved a role, minted, or dialed upstream.
	is.Equal(0, resolver.calls, "expired session must not resolve a role")
	is.Equal(0, minter.calls, "expired session must not mint credentials")
	is.Empty(conn.dialAddr, "expired session must not dial upstream")
}

// TestHandleConn_ExpiredSessionEmitsAuditEvent proves the supplementary
// activity-stream marker of ADR 0001 D13: the denied-for-reauth request Emits
// exactly one ConnEvent carrying the recognizable reason and the request facet.
// A normal (token present) request does not Emit this event — Evaluate already
// logs the served action.
func TestHandleConn_ExpiredSessionEmitsAuditEvent(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	conn := &fakeConn{
		incoming: bytes.NewReader([]byte(rawRequest(testPlaceholderAKID))),
		verdict:  pluginsdk.Verdict{Action: verdictAllow},
	}

	err := handleConn(context.Background(), conn, allowlist(testAccount), &fakeMinter{}, &fakeResolver{role: testRole}, testCredInstance, false)
	must.NoError(err)

	// Exactly one supplementary audit event for the denied-for-reauth request.
	must.Equal(1, conn.emitCalls)
	is.Contains(conn.emitEvent.Reason, "AWS SSO session expired")
	is.Contains(conn.emitEvent.Reason, testCredInstance)
	is.NotContains(conn.emitEvent.Reason, testSSOToken)
	// The event carries the request facet so the activity stream shows the action.
	is.Equal(testAccount, conn.emitEvent.Facets[fieldAccount])

	// A normal request with a live token does not Emit this marker.
	served := runAllowed(t, rawResp("200 OK", "application/json", `{"ok":true}`))
	is.Equal(0, served.emitCalls, "a served request must not emit the reauth marker")
}

// runAllowed drives the allow path against a canned raw upstream response and
// returns the fakeConn so the caller can assert what reached the agent and what
// was reported via SetResult.
func runAllowed(t *testing.T, rawResponse string) *fakeConn {
	t.Helper()

	mock := newMockSSOServer(t)
	conn := &fakeConn{
		incoming: bytes.NewReader([]byte(rawRequest(testPlaceholderAKID))),
		verdict:  pluginsdk.Verdict{Action: verdictAllow},
		upstream: &fakeUpstream{response: bytes.NewReader([]byte(rawResponse))},
	}

	err := handleConn(context.Background(), conn, allowlist(testAccount), mock.minter(), &fakeResolver{role: testRole}, testCredInstance, true)
	require.NoError(t, err)

	return conn
}

// rawResp frames a raw HTTP/1.1 response with a correct Content-Length for a
// fakeUpstream to serve.
func rawResp(statusLine, contentType, body string) string {
	return fmt.Sprintf(
		"HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
		statusLine, contentType, len(body), body,
	)
}

// agentResponse parses the response the handler wrote back to the agent and
// returns its status code and fully-read body.
func agentResponse(t *testing.T, conn *fakeConn) (status int, body []byte) {
	t.Helper()

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(conn.toAgent.Bytes())), nil)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, body
}

func TestReportResponse_SuccessStatusAndBodySample(t *testing.T) {
	t.Parallel()

	is := assert.New(t)

	const payload = `{"ok":true}`

	conn := runAllowed(t, rawResp("200 OK", "application/json", payload))

	// The agent received the complete, unmodified response.
	status, body := agentResponse(t, conn)
	is.Equal(http.StatusOK, status)
	is.Equal(payload, string(body))

	// SetResult reported the numeric status and a matching body sample.
	is.Equal(1, conn.resultCalls)
	is.Equal("200", conn.result[resultFieldStatus])
	is.Equal(payload, string(conn.resultSample))
}

func TestReportResponse_ErrorSurfacesAWSCode(t *testing.T) {
	t.Parallel()

	is := assert.New(t)

	// An S3-style XML error: the agent must still get the whole body, and the
	// reported status must be the AWS error code, not "403".
	const errBody = `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`

	conn := runAllowed(t, rawResp("403 Forbidden", "application/xml", errBody))

	status, body := agentResponse(t, conn)
	is.Equal(http.StatusForbidden, status)
	is.Equal(errBody, string(body), "the agent must receive the complete, unmodified error body")

	is.Equal(1, conn.resultCalls)
	is.Equal("AccessDenied", conn.result[resultFieldStatus])
}

func TestReportResponse_LargeBodyNotCorruptedAndSampleBounded(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	// A body larger than both the error-peek cap and the sample cap: the agent's
	// copy must be complete (the tee must not short or corrupt it), while the
	// reported sample is bounded.
	payload := bytes.Repeat([]byte("abcdefgh"), 8192) // 64 KiB

	conn := runAllowed(t, rawResp("200 OK", "application/octet-stream", string(payload)))

	status, body := agentResponse(t, conn)
	is.Equal(http.StatusOK, status)
	must.Len(body, len(payload), "the agent must receive the whole body")
	is.Equal(payload, body)

	is.Equal(1, conn.resultCalls)
	is.Equal("200", conn.result[resultFieldStatus])
	is.Len(conn.resultSample, responseSampleCap, "the sample is bounded to the cap")
	is.Equal(payload[:responseSampleCap], conn.resultSample, "the sample is a clean prefix")
}

func TestReportResponse_SetResultFailureIsBestEffort(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	const payload = "ok"

	mock := newMockSSOServer(t)
	conn := &fakeConn{
		incoming:  bytes.NewReader([]byte(rawRequest(testPlaceholderAKID))),
		verdict:   pluginsdk.Verdict{Action: verdictAllow},
		upstream:  &fakeUpstream{response: bytes.NewReader([]byte(rawResp("200 OK", "text/plain", payload)))},
		resultErr: errors.New("gateway result store unavailable"),
	}

	// A SetResult failure must not fail the request — the agent already has its
	// response.
	err := handleConn(context.Background(), conn, allowlist(testAccount), mock.minter(), &fakeResolver{role: testRole}, testCredInstance, true)
	must.NoError(err)

	_, body := agentResponse(t, conn)
	is.Equal(payload, string(body))
	is.Equal(1, conn.resultCalls)
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
		verdict:  pluginsdk.Verdict{Action: verdictAllow}, // even an allow verdict must not save it
	}
	minter := &fakeMinter{}
	resolver := &fakeResolver{role: testRole}

	// testAccount is not on the allowlist.
	err := handleConn(context.Background(), conn, allowlist("999999999999"), minter, resolver, testCredInstance, true)
	require.NoError(t, err)

	denied(t, conn, minter, resolver)
}

func TestHandleConn_NoAKIDDenied(t *testing.T) {
	t.Parallel()

	conn := &fakeConn{
		incoming: bytes.NewReader([]byte(rawRequestNoAuth())),
		verdict:  pluginsdk.Verdict{Action: verdictAllow},
	}
	minter := &fakeMinter{}
	resolver := &fakeResolver{role: testRole}

	err := handleConn(context.Background(), conn, allowlist(testAccount), minter, resolver, testCredInstance, true)
	require.NoError(t, err)

	denied(t, conn, minter, resolver)
}

// rawReq builds a minimal SigV4-signed request (placeholder AKID) for an
// arbitrary method/host/path, used to exercise the facet the example rules
// match on across representative read/write operations.
func rawReq(method, host, path string) string {
	return fmt.Sprintf(
		"%s %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Authorization: AWS4-HMAC-SHA256 Credential=%s/20200101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=deadbeef\r\n"+
			"Content-Length: 0\r\n"+
			"\r\n",
		method, path, host, testPlaceholderAKID,
	)
}

// TestFacetCoverage_ExampleRuleFields proves the plugin populates the aws facet
// fields the shipped examples/gateway.hcl rules reference — so those rules can
// match. It asserts the always-present anchors write gates use (method, action,
// service, account) and the best-effort iam_action reads allow on, across
// representative S3 read and write operations. A deny verdict lets the facet be
// captured without any mint.
func TestFacetCoverage_ExampleRuleFields(t *testing.T) {
	t.Parallel()

	const s3Host = "s3.us-east-1.amazonaws.com"

	tests := []struct {
		name, method, path string
		action, iamAction  string
	}{
		{"read object", http.MethodGet, "/bucket/key.txt", "GetObject", "s3:GetObject"},
		{"list bucket", http.MethodGet, "/bucket", "ListObjects", "s3:ListBucket"},
		{"write object", http.MethodPut, "/bucket/key.txt", "PutObject", "s3:PutObject"},
		{"delete object", http.MethodDelete, "/bucket/key.txt", "DeleteObject", "s3:DeleteObject"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			is := assert.New(t)
			must := require.New(t)

			conn := &fakeConn{
				incoming: bytes.NewReader([]byte(rawReq(tc.method, s3Host, tc.path))),
				verdict:  pluginsdk.Verdict{Action: verdictDeny}, // deny: capture the facet, no mint
			}

			err := handleConn(context.Background(), conn, allowlist(testAccount), &fakeMinter{}, &fakeResolver{role: testRole}, testCredInstance, true)
			must.NoError(err)
			must.NotNil(conn.evalAction)

			// Always-present anchors the example write gates key on.
			is.Equal(tc.method, conn.evalAction[fieldMethod])
			is.Equal(tc.action, conn.evalAction[fieldAction])
			is.Equal("s3", conn.evalAction[fieldService])
			is.Equal(testAccount, conn.evalAction[fieldAccount])

			// Best-effort iam_action the example reads-allow rule matches on.
			is.Equal(tc.iamAction, conn.evalAction[fieldIAMAction])
		})
	}
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
