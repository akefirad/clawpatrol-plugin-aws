package awssso

import (
	"context"
	"net"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/denoland/clawpatrol/pluginsdk"
)

// DialFunc brokers one upstream connection through the gateway. It matches
// pluginsdk.Conn.DialUpstream: the plugin runs Network=none (ADR 0001
// Capabilities), so every SSO API socket — like the final request dial — must
// be opened by the gateway on the plugin's behalf, never by the plugin's own
// (absent) network stack.
type DialFunc func(ctx context.Context, network, addr string, opts *pluginsdk.DialUpstreamOptions) (net.Conn, error)

// newSSOClient builds an anonymous-auth SSO client for the region whose every
// connection is brokered through dial (sso:GetRoleCredentials authenticates
// with the bearer token, not SigV4, so no signing credentials are needed).
func newSSOClient(region string, dial DialFunc) *sso.Client {
	return sso.New(sso.Options{
		Region:      region,
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  brokeredHTTPClient(dial),
	})
}

// brokeredHTTPClient returns an *http.Client whose transport opens every
// connection through the gateway's brokered dial. The gateway terminates
// upstream TLS and hands back a plaintext pipe, so the dial is wired as
// DialTLSContext: the transport treats the returned conn as the
// already-encrypted connection and runs no TLS of its own (a sandboxed plugin
// may have no CA bundle mounted). Mirrors the sibling plugin's brokeredHTTPClient.
func brokeredHTTPClient(dial DialFunc) *http.Client {
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}

			return dial(ctx, network, addr, &pluginsdk.DialUpstreamOptions{
				TLS:           true,
				TLSServerName: host,
			})
		},
	}

	return &http.Client{Transport: transport}
}
