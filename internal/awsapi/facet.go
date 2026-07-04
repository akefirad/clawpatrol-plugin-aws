package awsapi

import "github.com/denoland/clawpatrol/pluginsdk"

// FacetName is the short facet name declared by the plugin and referenced by
// the endpoint's Evaluate calls. The SDK auto-namespaces it to "aws.aws".
const FacetName = "aws"

// Facet field names. Shared between the facet declaration and the endpoint's
// per-request action map so the two never drift.
const (
	fieldService  = "service"
	fieldAccount  = "account"
	fieldRegion   = "region"
	fieldResource = "resource"
	fieldMethod   = "method"
)

// Facet is the minimal AWS facet for the first cut (ADR 0001 D12): the fields
// gateway CEL rules can match a request on. Richer fields (action,
// iam_action, account_name, response taps) are deferred to later slices.
func Facet() pluginsdk.FacetDef {
	return pluginsdk.FacetDef{
		Name: FacetName,
		Fields: []pluginsdk.FacetField{
			{Name: fieldService, Kind: pluginsdk.FacetString, Label: "Service", Description: "AWS service (from the request host)"},
			{Name: fieldAccount, Kind: pluginsdk.FacetString, Label: "Account", Description: "Target account (decoded from the request's access-key id)"},
			{Name: fieldRegion, Kind: pluginsdk.FacetString, Label: "Region", Description: "Signing region (from the request host)"},
			{Name: fieldResource, Kind: pluginsdk.FacetString, Label: "Resource", Description: "Request path"},
			{Name: fieldMethod, Kind: pluginsdk.FacetString, Label: "Method", Description: "HTTP method"},
		},
	}
}
