// Package plugin assembles the clawpatrol plugin declaration for the AWS SSO
// gateway: the aws_sso credential, the aws_api endpoint, and the aws facet.
package plugin

import (
	"github.com/akefirad/clawpatrol-plugin-aws/internal/awsapi"
	"github.com/denoland/clawpatrol/pluginsdk"
)

// Name is the registered plugin name; the gateway namespaces the plugin's
// types as "<Name>.<type>".
const Name = "aws"

// Version is informational, surfaced in the gateway's startup logs.
const Version = "0.1.0"

// New builds the plugin declaration handed to pluginsdk.Run.
//
// Capabilities: the plugin holds no network of its own (NetworkNone); every
// upstream connection goes through the gateway's audited brokered dial, scoped
// to the AWS service hosts via Egress.
func New() *pluginsdk.Plugin {
	return &pluginsdk.Plugin{
		Name:    Name,
		Version: Version,
		Capabilities: pluginsdk.Capabilities{
			Network: pluginsdk.NetworkNone,
			Egress:  []string{"*.amazonaws.com:443"},
		},
		Credentials: []pluginsdk.CredentialDef{awsapi.Credential()},
		Endpoints:   []pluginsdk.EndpointDef{awsapi.Endpoint()},
		Facets:      []pluginsdk.FacetDef{awsapi.Facet()},
	}
}
