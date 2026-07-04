package awsapi

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/pluginsdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The agent signs with the account's placeholder identity (ADR 0001 D5);
// the endpoint decodes the account from it and re-signs with seeded creds.
const (
	testPlaceholderAKID = "AKIA1234567890120000" // AKIA + account(123456789012) + padding
	testAccount         = "123456789012"
	testHost            = "sts.us-east-1.amazonaws.com"
	testBody            = `{"Action":"GetCallerIdentity","Version":"2011-06-15"}`

	seededAKID  = "ASIASEEDEDCREDS12345"
	seededToken = "SEEDED-SESSION-TOKEN"
)

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
	c.evalFacet = facet
	c.evalAction = action
	c.evalSummary = summary

	return c.verdict, nil
}

func (c *fakeConn) DialUpstream(_ context.Context, _, addr string, _ *pluginsdk.DialUpstreamOptions) (net.Conn, error) {
	c.dialAddr = addr
	return c.upstream, nil
}

func rawRequest() string {
	return fmt.Sprintf(
		"POST / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Authorization: AWS4-HMAC-SHA256 Credential=%s/20200101/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=deadbeef\r\n"+
			"X-Amz-Security-Token: PLACEHOLDER-TOKEN\r\n"+
			"Content-Type: application/x-amz-json-1.0\r\n"+
			"Content-Length: %d\r\n"+
			"\r\n%s",
		testHost, testPlaceholderAKID, len(testBody), testBody,
	)
}

func TestHandleConn_ReSignsWithSeededIdentityAndEvaluates(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	upstream := &fakeUpstream{
		response: bytes.NewReader([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")),
	}
	conn := &fakeConn{
		incoming: bytes.NewReader([]byte(rawRequest())),
		verdict:  pluginsdk.Verdict{Action: "allow"},
		upstream: upstream,
	}
	extras := map[string]string{
		"access_key_id":     seededAKID,
		"secret_access_key": "seededsecretaccesskey0000000000000000000",
		"session_token":     seededToken,
	}

	err := handleConn(context.Background(), conn, extras)
	must.NoError(err)

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

	// The outbound request carries the seeded identity, not the placeholder.
	out, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(upstream.written.Bytes())))
	must.NoError(err)

	authz := out.Header.Get("Authorization")
	is.Contains(authz, "Credential="+seededAKID+"/")
	is.NotContains(authz, testPlaceholderAKID)
	is.Equal(seededToken, out.Header.Get("X-Amz-Security-Token"))

	// The upstream body is preserved through the re-sign.
	body, err := io.ReadAll(out.Body)
	must.NoError(err)
	is.JSONEq(testBody, string(body))
}
