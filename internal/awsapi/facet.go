package awsapi

import "github.com/denoland/clawpatrol/pluginsdk"

// FacetName is the short facet name declared by the plugin and referenced by
// the endpoint's Evaluate calls. The SDK auto-namespaces it to "aws.aws".
const FacetName = "aws"

// Facet field names. Shared between the facet declaration and the endpoint's
// per-request action map so the two never drift.
const (
	fieldService   = "service"
	fieldAction    = "action"
	fieldIAMAction = "iam_action"
	fieldAccount   = "account"
	fieldRegion    = "region"
	fieldResource  = "resource"
	fieldMethod    = "method"
)

// Facet is the AWS facet gateway CEL rules match a request on (ADR 0001 D8).
//
// action is the CloudTrail operation name (the audit verb) — always present,
// so it is the facet's Title (the activity log shows it instead of the HTTP
// method). iam_action is the permission-shaped action, best-effort: it is
// Optional and omitted (not "") when undeterminable, so an allow rule matching
// on it fails closed rather than matching a guess (D8). account_name and the
// response taps stay deferred to later slices.
func Facet() pluginsdk.FacetDef {
	return pluginsdk.FacetDef{
		Name: FacetName,
		Fields: []pluginsdk.FacetField{
			{Name: fieldAction, Kind: pluginsdk.FacetString, Label: "Action", Description: "API action (CloudTrail operation)", Title: true},
			{Name: fieldIAMAction, Kind: pluginsdk.FacetString, Label: "IAM action", Description: "IAM policy action (best-effort; e.g. s3:GetObject)", Optional: true},
			{Name: fieldService, Kind: pluginsdk.FacetString, Label: "Service", Description: "AWS service (from the request host)", DetailOnly: true},
			{Name: fieldAccount, Kind: pluginsdk.FacetString, Label: "Account", Description: "Target account (decoded from the request's access-key id)"},
			{Name: fieldRegion, Kind: pluginsdk.FacetString, Label: "Region", Description: "Signing region (from the request host)"},
			{Name: fieldResource, Kind: pluginsdk.FacetString, Label: "Resource", Description: "Request path"},
			{Name: fieldMethod, Kind: pluginsdk.FacetString, Label: "Method", Description: "HTTP method"},
		},
	}
}
