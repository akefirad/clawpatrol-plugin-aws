// Package awsact turns an AWS request into the audit/policy semantics the aws
// facet exposes: the CloudTrail operation name (the audit verb) and the
// IAM-shaped action string. Both are pure functions of the request and the
// SigV4 signing service (derived from the host by awssign) so the gateway's CEL
// rules bind to them without any live AWS call.
package awsact

import (
	"net/http"
	"net/url"
	"strings"
)

// Action derives the CloudTrail operation name (the audit verb, aws.action)
// from a request. It is always non-empty:
//
//   - S3 is a REST service — the operation is implied by method + addressing +
//     subresource, never carried on the wire — so it is reconstructed (see
//     s3Operation): DELETE /bucket/key -> "DeleteObject", GET /bucket?versions
//     -> "ListObjectVersions".
//   - JSON-protocol services carry it in X-Amz-Target
//     ("DynamoDB_20120810.PutItem" -> "PutItem").
//   - Query-protocol services carry an Action parameter, in the URL query for
//     GET or in the form-encoded body for POST ("DescribeInstances").
//   - Otherwise the verb is unknowable and it falls back to "METHOD path",
//     which matches no read prefix and is therefore gated as a mutation.
//
// body is the already-read request body; service is the SigV4 signing name.
func Action(req *http.Request, body []byte, service string) string {
	if service == "s3" {
		return s3Operation(req)
	}

	if target := req.Header.Get("X-Amz-Target"); target != "" {
		if i := strings.LastIndexByte(target, '.'); i >= 0 {
			return target[i+1:]
		}

		return target
	}

	if a := req.URL.Query().Get("Action"); a != "" {
		return a
	}

	if a := formAction(req.Header.Get("Content-Type"), body); a != "" {
		return a
	}

	return req.Method + " " + req.URL.Path
}

// formAction returns the Action field of a query-protocol request's
// form-encoded body, or "" when the request is not form-encoded or carries no
// Action. AWS query-protocol services POST
// "Action=DescribeInstances&Version=…" as application/x-www-form-urlencoded.
func formAction(contentType string, body []byte) string {
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		return ""
	}

	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return ""
	}

	return vals.Get("Action")
}
