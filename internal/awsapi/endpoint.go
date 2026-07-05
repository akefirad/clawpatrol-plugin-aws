package awsapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
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

// maxRequestBodyBytes bounds how much of an agent request body the plugin reads
// into memory. The re-sign hashes the whole payload, so the body is necessarily
// buffered; without a cap an agent could stream an unbounded body and exhaust
// the plugin's memory. 100 MiB comfortably covers ordinary API calls and a
// single S3 (multipart) part while bounding the per-connection footprint; a
// request over it is rejected with a 413. Tune here if larger single-PUT uploads
// through the gateway become a real need.
const maxRequestBodyBytes int64 = 100 << 20 // 100 MiB

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
	Emit(ev pluginsdk.ConnEvent)
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

			// The plugin runs Network=none (ADR 0001 Capabilities): the SSO
			// client's GetRoleCredentials/ListAccountRoles calls must reach
			// portal.sso.<region>.amazonaws.com through the gateway's brokered
			// dial, exactly like the final request dial below — never the SDK's
			// default (direct) transport.
			minter := awssso.New(region, token, credentialExpiryWindow, conn.DialUpstream)
			resolver := awssso.NewRoles(region, token, conn.DialUpstream)

			// An empty token is an expired SSO session with no valid refresh (ADR
			// 0001 D13): the gateway delivers no CredentialSecret. Thread the
			// credential instance name so a would-be-served request can surface a
			// recognizable re-auth error instead of failing at mint.
			//
			// TODO: hasToken (token != "") is captured once, at connection open, and
			// held for the connection's lifetime. A token that expires mid-connection
			// is not re-observed here, so such a request skips the D13 re-auth surface
			// and instead fails at mint — answered by the S4 bounded 5xx, not the
			// recognizable re-auth error. This is acceptable because the gateway
			// re-delivers the token as CredentialSecret per connection (ADR 0001 D9 /
			// request flow), so the next connection re-reads it; revisit if a
			// long-lived keep-alive connection makes mid-connection expiry common.
			err = handleConn(ctx, conn, conn.UpstreamHost, maxRequestBodyBytes, allow, minter, resolver, conn.CredentialInstance, token != "")
			if err != nil {
				// The gateway closes the conn on a HandleConn error with no
				// response to the agent, so without this the failure is silent
				// (GH-16). go-plugin surfaces plugin stderr in the gateway log.
				// The wrapped error carries request context (account, host) but
				// never a token or minted secret.
				log.Printf("aws_api: connection for credential %q failed: %v", conn.CredentialInstance, err)
			}

			return err
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
func handleConn(ctx context.Context, conn gatewayConn, upstreamHost string, maxBody int64, allow map[string]struct{}, minter roleMinter, resolver roleResolver, credInstance string, hasToken bool) error {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return fmt.Errorf("read request: %w", err)
		}

		closeConn, err := handleRequest(ctx, conn, req, upstreamHost, maxBody, allow, minter, resolver, credInstance, hasToken)
		if err != nil {
			return err
		}

		if closeConn {
			return nil
		}
	}
}

// readBoundedBody acknowledges Expect: 100-continue, reads the request body
// bounded to maxBody bytes, and normalizes an aws-chunked body to its raw
// payload. It returns tooLarge=true when the body exceeds the cap so the caller
// answers a bounded 413. The ack and read run only after the fail-closed gates,
// so a denied request is never invited to stream its payload; io.LimitReader
// caps memory at maxBody+1 even if the agent ignores the ack and streams more.
func readBoundedBody(conn io.Writer, req *http.Request, maxBody int64) (body []byte, tooLarge bool, err error) {
	if err := awssign.Ack100Continue(conn, req.Header); err != nil {
		return nil, false, fmt.Errorf("ack 100-continue: %w", err)
	}

	body, err = io.ReadAll(io.LimitReader(req.Body, maxBody+1))
	_ = req.Body.Close()

	if err != nil {
		return nil, false, fmt.Errorf("read request body: %w", err)
	}

	if int64(len(body)) > maxBody {
		return nil, true, nil
	}

	// Decode aws-chunked upload bodies to the raw payload and drop the framing /
	// checksum headers the from-scratch re-sign won't reproduce, so writes don't
	// fail SignatureDoesNotMatch. A non-chunked body passes through unchanged.
	body, err = awssign.NormalizeChunked(req, body)
	if err != nil {
		return nil, false, fmt.Errorf("normalize request body: %w", err)
	}

	return body, false, nil
}

// handleRequest processes one request. It returns closeConn=true when the
// connection must not be reused: either the agent asked (req.Close), or the
// request was answered before its body was drained (the fail-closed gates and
// the over-cap guard skip the body, so the undrained bytes make the stream
// unsafe to parse the next request from).
func handleRequest(ctx context.Context, conn gatewayConn, req *http.Request, upstreamHost string, maxBody int64, allow map[string]struct{}, minter roleMinter, resolver roleResolver, credInstance string, hasToken bool) (closeConn bool, err error) {
	// The fail-closed authorization gates run on the request line and headers
	// alone, before Expect: 100-continue is acknowledged and before the body is
	// read (S3): a request that will be denied here must never be invited to
	// stream its payload nor have it buffered. These denials skip the body, so
	// its bytes are left undrained and the connection is closed (closeConn=true)
	// rather than reused.
	akid, ok := awssign.CredentialAKID(req.Header.Get("Authorization"))
	if !ok {
		return true, writeError(conn, req, "aws_api: request is not SigV4-signed")
	}

	account, ok := awssign.AccountFromAKID(akid)
	if !ok {
		return true, writeError(conn, req, "aws_api: no account encoded in the access-key id")
	}

	// Fail closed: an account outside the explicit allowlist is denied before
	// any policy evaluation, role resolution, or mint (ADR 0001 D4).
	if _, allowed := allow[account]; !allowed {
		return true, writeError(conn, req, "aws_api: account "+account+" is not on the allowlist")
	}

	// Fail closed when the agent-controlled Host header diverges from the host the
	// gateway routed this connection to (S2): the routed host is the endpoint's
	// policy-scoping key, and the facet service/region, the dial target, and the
	// TLS SNI below are all derived from req.Host. Without this an agent could
	// reach an SNI-scoped endpoint and address a different service via Host — a
	// confused-deputy escape — so a mismatch is answered before any SSO work.
	if !hostMatchesRoute(req.Host, upstreamHost) {
		return true, writeErrorResponse(conn, req, http.StatusMisdirectedRequest,
			"aws_api: request Host does not match the routed endpoint host")
	}

	// The request is authorized to reach AWS: only now invite and read the body
	// (bounded), so a denied request is never asked to stream its payload.
	body, tooLarge, err := readBoundedBody(conn, req, maxBody)
	if err != nil {
		return false, err
	}

	if tooLarge {
		// The over-cap remainder is left undrained, so the connection is closed.
		return true, writeErrorResponse(conn, req, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("aws_api: request body exceeds the %d-byte limit", maxBody))
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
		return false, fmt.Errorf("evaluate %s: %w", summary, err)
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
		// deny, hitl_deny, error, or any unrecognized action: fail closed. The
		// body was read above, so the stream is drained and the connection may be
		// reused unless the agent asked to close it.
		//
		// verdict.Reason is operator-authored rule text (the gateway does not fill
		// it from agent input), so reflecting it verbatim to the agent is a
		// conscious decision (m1): it is a useful, low-risk diagnostic that tells
		// the agent why it was blocked, and surfacing operator text to a
		// potentially-compromised agent leaks nothing the operator did not choose
		// to write into the rule.
		return req.Close, writeError(conn, req, "aws_api: "+verdict.Reason)
	}

	// The verdict would let this request through, but the SSO session expired with
	// no live token (empty CredentialSecret). Surface the re-auth need actively
	// instead of failing opaquely at mint (ADR 0001 D13): deny with a recognizable
	// error naming the credential. The token-needing step (role resolve + mint) is
	// never reached, so no SSO work happens on this path.
	if !hasToken {
		reason := reauthReason(credInstance)

		// Supplementary activity-stream marker (ADR 0001 D13): the Connect card is
		// the primary expiry signal, but an audit event makes the denied request
		// visible in the stream. It is a session condition, not a rule verdict, so
		// it is emitted as an error event — not a fabricated allow/deny.
		conn.Emit(pluginsdk.ConnEvent{
			Action:  connEventError,
			Reason:  reason,
			Verb:    action,
			Summary: summary,
			Facets:  facet,
		})

		return req.Close, writeError(conn, req, reason)
	}

	if err := forwardRequest(ctx, conn, req, body, account, host, service, region, minter, resolver); err != nil {
		// Tag the error with the account and host so the HandleConn log names the
		// failing request (the underlying wraps already carry the SSO/dial detail).
		return false, fmt.Errorf("forward request for account %s to %s: %w", account, host, err)
	}

	return req.Close, nil
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

// connEventError is the ConnEvent.Action for the supplementary re-auth audit
// marker (ADR 0001 D13). The event records a session condition (an expired SSO
// token), not a rule decision, so it uses "error" rather than a fabricated
// allow/deny verdict no rule produced.
const connEventError = "error"

// forwardRequest runs the allowed path: auto-discover (and cache) the account's
// role, mint short-lived SSO credentials, re-sign, and proxy upstream via the
// gateway's brokered dial. It runs only after the verdict allows, so a denied
// request never resolves a role or mints (ADR 0001 request flow). The role is
// cached per account and the minter caches per (account, role).
//
// Every failure that happens before the upstream response starts streaming to
// the agent (role resolution — including the "account grants multiple roles"
// misconfig — minting, re-signing, the dial, and the upstream write/read) is
// answered with a bounded 5xx (S4) so the agent sees a real error status rather
// than a bare connection reset; the wrapped error is still returned so
// HandleConn logs the SSO/dial detail. The agent-facing reasons stay generic —
// the diagnostic detail belongs in the operator's log, not a possibly
// compromised agent. A reportResponse failure happens mid-stream, once the
// agent is already receiving bytes, so no clean 5xx can replace it.
func forwardRequest(ctx context.Context, conn gatewayConn, req *http.Request, body []byte, account, host, service, region string, minter roleMinter, resolver roleResolver) error {
	role, err := resolver.Role(ctx, account)
	if err != nil {
		_ = writeErrorResponse(conn, req, http.StatusBadGateway, "aws_api: could not resolve a role for the target account")

		return fmt.Errorf("resolve role for account %s: %w", account, err)
	}

	creds, err := minter.Credentials(ctx, account, role)
	if err != nil {
		_ = writeErrorResponse(conn, req, http.StatusBadGateway, "aws_api: could not mint credentials for the request")

		return fmt.Errorf("mint credentials: %w", err)
	}

	signed, err := awssign.SignRequest(ctx, req, host, body, service, region, creds)
	if err != nil {
		_ = writeErrorResponse(conn, req, http.StatusBadGateway, "aws_api: could not sign the request")

		return fmt.Errorf("re-sign: %w", err)
	}

	upstream, err := conn.DialUpstream(ctx, "tcp", net.JoinHostPort(host, upstreamPort), &pluginsdk.DialUpstreamOptions{
		TLS:           true,
		TLSServerName: host,
	})
	if err != nil {
		_ = writeErrorResponse(conn, req, http.StatusBadGateway, "aws_api: could not reach the upstream service")

		return fmt.Errorf("dial upstream %s: %w", host, err)
	}
	defer func() { _ = upstream.Close() }()

	if err := signed.Write(upstream); err != nil {
		_ = writeErrorResponse(conn, req, http.StatusBadGateway, "aws_api: could not send the request upstream")

		return fmt.Errorf("write upstream request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstream), signed)
	if err != nil {
		_ = writeErrorResponse(conn, req, http.StatusBadGateway, "aws_api: no valid response from the upstream service")

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
// request (the AKID/account/allowlist gates and the D13 re-auth deny).
func writeError(conn io.Writer, req *http.Request, reason string) error {
	return writeErrorResponse(conn, req, http.StatusForbidden, reason)
}

// writeErrorResponse writes a minimal, bounded HTTP error back to the agent — a
// real status code with the reason line as the only body — instead of tearing
// the connection down with no response. It is the single path every non-success
// outcome routes through (the deny/malformed 403s, the Host/SNI-divergence 421,
// the body-cap 413, and the mint/dial 5xx), so the body is never unbounded and
// nothing beyond the operator/plugin reason is echoed to the agent.
func writeErrorResponse(conn io.Writer, req *http.Request, statusCode int, reason string) error {
	if reason == "" {
		reason = "aws_api: request denied"
	}

	body := []byte(reason + "\n")
	resp := &http.Response{
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		StatusCode:    statusCode,
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

// hostMatchesRoute reports whether the agent-controlled HTTP Host header
// addresses the same host the gateway routed this connection to
// (conn.UpstreamHost, recovered from SNI / the VIP table before TLS
// termination). The gateway scopes the endpoint's policy by that routed host, so
// an agent that reached an s3.amazonaws.com endpoint must not then address
// dynamodb.amazonaws.com via the Host header — a confused-deputy escape of the
// endpoint's scope. When the routed host is unavailable (an older gateway that
// does not send it, or a direct-IP dispatch with no SNI to compare) there is
// nothing to check against and the request proceeds; the plugin's
// *.amazonaws.com:443 egress capability remains the backstop.
func hostMatchesRoute(reqHost, routedHost string) bool {
	if routedHost == "" {
		return true
	}

	return strings.EqualFold(hostOnly(reqHost), hostOnly(routedHost))
}

// hostOnly strips any :port suffix, returning the bare host for comparison.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}

	return hostport
}
