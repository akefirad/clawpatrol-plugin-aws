package awsapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/denoland/clawpatrol/pluginsdk"

	"github.com/akefirad/clawpatrol-plugin-aws/internal/awssign"
	"github.com/akefirad/clawpatrol-plugin-aws/internal/awssso"
)

// EndpointTypeName is the HCL endpoint type this plugin registers.
const EndpointTypeName = "aws_api"

// credentialExpiryWindow is the refresh margin applied to every cached minted
// credential: the CredentialsCache mints afresh once a role's temporary
// credentials fall inside this window of their expiration.
const credentialExpiryWindow = 5 * time.Minute

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
			region, token, role, err := endpointParams(conn.CredentialCanonicalConfig, conn.CredentialSecret)
			if err != nil {
				return err
			}

			minter := awssso.New(region, token, credentialExpiryWindow)

			return handleConn(ctx, conn, minter, role)
		},
	}
}

// endpointParams reads the per-connection minting inputs off the gateway's
// delivery: the SSO region and configured role from the credential's canonical
// config, and the SSO access token from the credential's secret bytes (ADR
// 0001 D9 — the gateway's OAuth flow delivers the token as
// Conn.CredentialSecret). The account is not read here; it is decoded per
// request from the SigV4 access-key id (ADR 0001 D5).
func endpointParams(canonicalConfig, secret []byte) (region, token, role string, err error) {
	var cfg ssoConfig
	if err := json.Unmarshal(canonicalConfig, &cfg); err != nil {
		return "", "", "", fmt.Errorf("decode aws_sso credential config: %w", err)
	}

	return cfg.Region, string(secret), cfg.RoleName, nil
}

// upstreamPort is the AWS HTTPS port every brokered dial targets.
const upstreamPort = "443"

// roleMinter is the slice of *awssso.Minter that handleConn needs: mint (or
// serve cached) temporary credentials for a target account and role. Narrowing
// to an interface keeps handleConn unit-testable.
type roleMinter interface {
	Credentials(ctx context.Context, account, role string) (aws.Credentials, error)
}

// handleConn owns one agent connection: read each HTTP request, decode the
// target account from the SigV4 access-key id, evaluate the aws facet, mint
// short-lived SSO credentials for the configured role, re-sign with them, and
// proxy upstream via the gateway's dial.
//
// Credentials are minted live via sso:GetRoleCredentials and cached per
// (account, role) by the minter (ADR 0001 D12): a burst reuses one mint, and
// minting happens only after the verdict allows the request.
func handleConn(ctx context.Context, conn gatewayConn, minter roleMinter, role string) error {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return fmt.Errorf("read request: %w", err)
		}

		if err := handleRequest(ctx, conn, req, minter, role); err != nil {
			return err
		}

		if req.Close {
			return nil
		}
	}
}

func handleRequest(ctx context.Context, conn gatewayConn, req *http.Request, minter roleMinter, role string) error {
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

	// Mint only after the verdict allows, so a denied request never mints
	// (ADR 0001 request flow). The minter caches per (account, role).
	creds, err := minter.Credentials(ctx, account, role)
	if err != nil {
		return fmt.Errorf("mint credentials: %w", err)
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
