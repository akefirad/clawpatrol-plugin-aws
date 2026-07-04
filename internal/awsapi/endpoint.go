package awsapi

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/denoland/clawpatrol/pluginsdk"

	"github.com/akefirad/clawpatrol-plugin-aws/internal/awssign"
)

// EndpointTypeName is the HCL endpoint type this plugin registers.
const EndpointTypeName = "aws_api"

// gatewayConn is the slice of *pluginsdk.Conn that handleConn needs: the
// duplex agent connection plus the gateway's Evaluate and brokered DialUpstream
// hooks. Narrowing to an interface lets the handler be driven by a fake in
// tests — the SDK's Conn wires those hooks with unexported fields no external
// test can populate.
type gatewayConn interface {
	io.Reader
	io.Writer
	Evaluate(ctx context.Context, facet string, action map[string]any, summary string) (pluginsdk.Verdict, error)
	DialUpstream(ctx context.Context, network, addr string, opts *pluginsdk.DialUpstreamOptions) (net.Conn, error)
}

// Endpoint declares the aws_api endpoint. It carries only `hosts` (injected by
// the gateway framework) — no role, no region (ADR 0001 D6); per-request state
// lives on the credential. The gateway terminates agent TLS before HandleConn.
func Endpoint() pluginsdk.EndpointDef {
	return pluginsdk.EndpointDef{
		TypeName: EndpointTypeName,
		Family:   FacetName,
		TLSMode:  pluginsdk.TLSTerminate,
		HandleConn: func(ctx context.Context, conn *pluginsdk.Conn) error {
			return handleConn(ctx, conn, conn.CredentialExtras)
		},
	}
}

// upstreamPort is the AWS HTTPS port every brokered dial targets.
const upstreamPort = "443"

// handleConn owns one agent connection: read each HTTP request, decode the
// target account from the SigV4 access-key id, evaluate the aws facet, re-sign
// with the seeded credentials, and proxy upstream via the gateway's dial.
//
// In this first cut the credentials are seeded (ADR 0001 D12): they arrive on
// CredentialExtras (access_key_id / secret_access_key / session_token), which
// is forward-compatible with later slices that mint them via SSO.
func handleConn(ctx context.Context, conn gatewayConn, extras map[string]string) error {
	creds := credentialsFromExtras(extras)

	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return fmt.Errorf("read request: %w", err)
		}

		if err := handleRequest(ctx, conn, req, creds); err != nil {
			return err
		}

		if req.Close {
			return nil
		}
	}
}

// credentialsFromExtras reads the seeded AWS credentials the gateway delivers
// on CredentialExtras.
func credentialsFromExtras(extras map[string]string) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     extras["access_key_id"],
		SecretAccessKey: extras["secret_access_key"],
		SessionToken:    extras["session_token"],
	}
}

func handleRequest(ctx context.Context, conn gatewayConn, req *http.Request, creds aws.Credentials) error {
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()

	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}

	akid, ok := awssign.CredentialAKID(req.Header.Get("Authorization"))
	if !ok {
		return writeError(conn, req, "aws_api: request is not SigV4-signed")
	}

	account, ok := awssign.AccountFromAKID(akid)
	if !ok {
		return writeError(conn, req, "aws_api: no account encoded in the access-key id")
	}

	host := req.Host
	service, region := awssign.ParseServiceRegion(host)

	action := map[string]any{
		"service":  service,
		"account":  account,
		"region":   region,
		"resource": req.URL.Path,
		"method":   req.Method,
	}
	summary := fmt.Sprintf("%s %s (%s/%s)", req.Method, service, account, region)

	verdict, err := conn.Evaluate(ctx, FacetName, action, summary)
	if err != nil {
		return fmt.Errorf("evaluate %s: %w", summary, err)
	}

	switch verdict.Action {
	case "allow", "hitl_allow":
		// proceed
	default:
		return writeError(conn, req, "aws_api: "+verdict.Reason)
	}

	signed, err := awssign.SignRequest(ctx, req, host, body, service, region, creds)
	if err != nil {
		return fmt.Errorf("re-sign: %w", err)
	}

	upstream, err := conn.DialUpstream(ctx, "tcp", net.JoinHostPort(host, upstreamPort), &pluginsdk.DialUpstreamOptions{
		TLS:           true,
		TLSServerName: host,
	})
	if err != nil {
		return fmt.Errorf("dial upstream %s: %w", host, err)
	}
	defer func() { _ = upstream.Close() }()

	if err := signed.Write(upstream); err != nil {
		return fmt.Errorf("write upstream request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstream), signed)
	if err != nil {
		return fmt.Errorf("read upstream response: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if err := resp.Write(conn); err != nil {
		return fmt.Errorf("write response to agent: %w", err)
	}

	return nil
}

// writeError sends a minimal 403 back to the agent for a denied or malformed
// request. Richer, recognizable re-auth errors (ADR 0001 D13) are a later slice.
func writeError(conn io.Writer, req *http.Request, reason string) error {
	if reason == "" {
		reason = "aws_api: request denied"
	}

	body := []byte(reason + "\n")
	resp := &http.Response{
		Status:        "403 Forbidden",
		StatusCode:    http.StatusForbidden,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}

	return resp.Write(conn)
}
