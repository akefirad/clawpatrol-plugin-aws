package awsapi

import (
	"context"
	"io"
	"net"

	"github.com/denoland/clawpatrol/pluginsdk"
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

// handleConn owns one agent connection: read the HTTP request, decode the
// target account from the SigV4 access-key id, evaluate the aws facet, re-sign
// with the seeded credentials, and proxy upstream via the gateway's dial.
//
// STUB: implemented in the seam-2 green step.
func handleConn(_ context.Context, _ gatewayConn, _ map[string]string) error {
	return nil
}
