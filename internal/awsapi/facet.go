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
// on it fails closed rather than matching a guess (D8).
//
// ResultFields are reported after the upstream response via Conn.SetResult:
// status (the HTTP code, or the AWS error code on a 4xx/5xx) is the result
// Title; response_body is a bounded body sample (a FacetStream the gateway
// caps). account_name (Organizations) stays deferred to a later slice.
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
		ResultFields: []pluginsdk.FacetField{
			{Name: resultFieldStatus, Kind: pluginsdk.FacetString, Label: "Status", Description: "HTTP status code, or AWS error code on a 4xx/5xx", Title: true},
			{Name: resultFieldResponseBody, Kind: pluginsdk.FacetStream, Label: "Response body", Description: "Bounded sample of the upstream response body"},
		},
	}
}
