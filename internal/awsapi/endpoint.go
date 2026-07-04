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

	"github.com/akefirad/clawpatrol-plugin-aws/internal/awsact"
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
	SetResult(ctx context.Context, result map[string]any) error
}

// resultConn is the slice of gatewayConn reportResponse needs: write the
// response back to the agent and report its outcome via SetResult.
type resultConn interface {
	io.Writer
	SetResult(ctx context.Context, result map[string]any) error
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
			region, token, accounts, err := endpointParams(conn.CredentialCanonicalConfig, conn.CredentialSecret)
			if err != nil {
				return err
			}

			allow := make(map[string]struct{}, len(accounts))
			for _, id := range accounts {
				allow[id] = struct{}{}
			}

			minter := awssso.New(region, token, credentialExpiryWindow)
			resolver := awssso.NewRoles(region, token)

			// An empty token is an expired SSO session with no valid refresh (ADR
			// 0001 D13): the gateway delivers no CredentialSecret. Thread the
			// credential instance name so a would-be-served request can surface a
			// recognizable re-auth error instead of failing at mint.
			return handleConn(ctx, conn, allow, minter, resolver, conn.CredentialInstance, token != "")
		},
	}
}

// endpointParams reads the per-connection minting inputs off the gateway's
// delivery: the SSO region and the account allowlist from the credential's
// canonical config, and the SSO access token from the credential's secret
// bytes (ADR 0001 D9 — the gateway's OAuth flow delivers the token as
// Conn.CredentialSecret). The target account is not read here; it is decoded
// per request from the SigV4 access-key id (ADR 0001 D5) and matched against
// the allowlist. The role is auto-discovered per account, not configured.
func endpointParams(canonicalConfig, secret []byte) (region, token string, accounts []string, err error) {
	var cfg ssoConfig
	if err := json.Unmarshal(canonicalConfig, &cfg); err != nil {
		return "", "", nil, fmt.Errorf("decode aws_sso credential config: %w", err)
	}

	return cfg.Region, string(secret), cfg.Accounts, nil
}

// upstreamPort is the AWS HTTPS port every brokered dial targets.
const upstreamPort = "443"

// roleMinter is the slice of *awssso.Minter that handleConn needs: mint (or
// serve cached) temporary credentials for a target account and role. Narrowing
// to an interface keeps handleConn unit-testable.
type roleMinter interface {
	Credentials(ctx context.Context, account, role string) (aws.Credentials, error)
}

// roleResolver is the slice of *awssso.Roles that handleConn needs:
// auto-discover (and cache) the single role for an account via
// sso:ListAccountRoles (ADR 0001 D3). Narrowing to an interface keeps
// handleConn unit-testable.
type roleResolver interface {
	Role(ctx context.Context, account string) (string, error)
}

// handleConn owns one agent connection: read each HTTP request, decode the
// target account from the SigV4 access-key id, fail closed unless the account
// is on the allowlist, evaluate the aws facet, resolve and mint short-lived
// SSO credentials for the account's role, re-sign with them, and proxy
// upstream via the gateway's dial.
//
// Dispatch is fail-closed (ADR 0001 D4/D5): a request with no parseable AKID,
// or whose decoded account is not on the allowlist, is denied without
// resolving a role, minting, or re-signing. Credentials are minted live via
// sso:GetRoleCredentials and cached per (account, role) by the minter (ADR
// 0001 D12): a burst reuses one mint, and minting happens only after the
// verdict allows the request.
func handleConn(ctx context.Context, conn gatewayConn, allow map[string]struct{}, minter roleMinter, resolver roleResolver, credInstance string, hasToken bool) error {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return fmt.Errorf("read request: %w", err)
		}

		if err := handleRequest(ctx, conn, req, allow, minter, resolver, credInstance, hasToken); err != nil {
			return err
		}

		if req.Close {
			return nil
		}
	}
}

func handleRequest(ctx context.Context, conn gatewayConn, req *http.Request, allow map[string]struct{}, minter roleMinter, resolver roleResolver, credInstance string, hasToken bool) error {
	// Acknowledge Expect: 100-continue before reading the body so an agent that
	// waits for the go-ahead (S3 uploads do) streams it (ADR 0001 D12 write path).
	if err := awssign.Ack100Continue(conn, req.Header); err != nil {
		return fmt.Errorf("ack 100-continue: %w", err)
	}

	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()

	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}

	// Decode aws-chunked upload bodies to the raw payload and drop the framing /
	// checksum headers the from-scratch re-sign won't reproduce, so writes don't
	// fail SignatureDoesNotMatch. A non-chunked body passes through unchanged.
	body, err = awssign.NormalizeChunked(req, body)
	if err != nil {
		return fmt.Errorf("normalize request body: %w", err)
	}

	akid, ok := awssign.CredentialAKID(req.Header.Get("Authorization"))
	if !ok {
		return writeError(conn, req, "aws_api: request is not SigV4-signed")
	}

	account, ok := awssign.AccountFromAKID(akid)
	if !ok {
		return writeError(conn, req, "aws_api: no account encoded in the access-key id")
	}

	// Fail closed: an account outside the explicit allowlist is denied before
	// any policy evaluation, role resolution, or mint (ADR 0001 D4).
	if _, allowed := allow[account]; !allowed {
		return writeError(conn, req, "aws_api: account "+account+" is not on the allowlist")
	}

	host := req.Host
	service, region := awssign.ParseServiceRegion(host)
	action := awsact.Action(req, body, service)

	facet := map[string]any{
		fieldService:  service,
		fieldAction:   action,
		fieldAccount:  account,
		fieldRegion:   region,
		fieldResource: req.URL.Path,
		fieldMethod:   req.Method,
	}

	// iam_action is best-effort: omitted (not "") when undeterminable, so a
	// rule matching on it fails closed rather than matching a guess (D8).
	if iamAction, ok := awsact.IAMAction(service, action); ok {
		facet[fieldIAMAction] = iamAction
	}

	summary := fmt.Sprintf("%s (%s/%s)", action, account, region)

	verdict, err := conn.Evaluate(ctx, FacetName, facet, summary)
	if err != nil {
		return fmt.Errorf("evaluate %s: %w", summary, err)
	}

	// Synchronous HITL (ADR 0001 request flow): Evaluate walks the approve chain
	// and blocks until the decision, so by here the verdict is final. allow and
	// hitl_allow proceed identically — the mint happens below, after the verdict,
	// so a request approved after a delay is signed with fresh credentials.
	// deny/hitl_deny block with no SSO work; any unknown action fails closed.
	switch verdict.Action {
	case verdictAllow, verdictHITLAllow:
		// proceed
	default:
		// deny, hitl_deny, error, or any unrecognized action: fail closed.
		return writeError(conn, req, "aws_api: "+verdict.Reason)
	}

	// The verdict would let this request through, but the SSO session expired with
	// no live token (empty CredentialSecret). Surface the re-auth need actively
	// instead of failing opaquely at mint (ADR 0001 D13): deny with a recognizable
	// error naming the credential. The token-needing step (role resolve + mint) is
	// never reached, so no SSO work happens on this path.
	if !hasToken {
		return writeError(conn, req, reauthReason(credInstance))
	}

	return forwardRequest(ctx, conn, req, body, account, host, service, region, minter, resolver)
}

// reauthReason is the recognizable re-auth error surfaced to the agent when the
// SSO session has expired (ADR 0001 D13). It names the credential instance and
// directs the operator to reconnect in the clawpatrol dashboard — no dashboard
// URL is configured in this cut, and no token or credential material is included.
func reauthReason(credInstance string) string {
	return fmt.Sprintf(
		"aws_sso: AWS SSO session expired; an operator must reconnect the %q credential in the clawpatrol dashboard",
		credInstance,
	)
}

// Verdict actions the gateway returns (pluginsdk.Verdict.Action). allow and
// hitl_allow permit the request to proceed; deny and hitl_deny block it, as
// does any unrecognized action (fail closed).
const (
	verdictAllow     = "allow"
	verdictHITLAllow = "hitl_allow"
	verdictDeny      = "deny"
	verdictHITLDeny  = "hitl_deny"
)

// forwardRequest runs the allowed path: auto-discover (and cache) the account's
// role, mint short-lived SSO credentials, re-sign, and proxy upstream via the
// gateway's brokered dial. It runs only after the verdict allows, so a denied
// request never resolves a role or mints (ADR 0001 request flow). The role is
// cached per account and the minter caches per (account, role).
func forwardRequest(ctx context.Context, conn gatewayConn, req *http.Request, body []byte, account, host, service, region string, minter roleMinter, resolver roleResolver) error {
	role, err := resolver.Role(ctx, account)
	if err != nil {
		return fmt.Errorf("resolve role for account %s: %w", account, err)
	}

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

	// Write the response to the agent and report its outcome (status + a bounded
	// body sample) to the gateway via SetResult (ADR 0001 D8 result fields).
	if err := reportResponse(ctx, conn, resp); err != nil {
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
