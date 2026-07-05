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
//   - JSON-protocol services (DynamoDB, SQS-json, CloudWatch, …) send
//     application/x-amz-json-* and carry the operation in X-Amz-Target
//     ("DynamoDB_20120810.PutItem" -> "PutItem").
//   - Query-protocol services (EC2, IAM, RDS, STS, SNS, SQS, …) carry an Action
//     parameter, form-encoded in the body for POST or in the URL query for GET
//     ("DescribeInstances").
//   - Otherwise the verb is unknowable and it falls back to "METHOD path",
//     which matches no read prefix and is therefore gated as a mutation.
//
// The wire protocol is read from Content-Type rather than trusting whichever
// slot the agent filled, because the two protocols dispatch on different fields
// and an agent can populate both. AWS query-protocol services ignore
// X-Amz-Target and execute the Action parameter; JSON-protocol services ignore
// the Action parameter and execute X-Amz-Target. Classifying by the field AWS
// does *not* consult would let a compromised agent mask a write as a read (send
// X-Amz-Target: …DescribeInstances with a body Action=TerminateInstances to EC2,
// or a ?Action=GetItem decoy with X-Amz-Target: …DeleteItem to DynamoDB). So the
// operation is always read from the field the routed service actually executes.
//
// body is the already-read request body; service is the SigV4 signing name.
func Action(req *http.Request, body []byte, service string) string {
	if service == "s3" {
		return s3Operation(req)
	}

	contentType := req.Header.Get("Content-Type")

	switch {
	case strings.HasPrefix(contentType, "application/x-amz-json"):
		// JSON-protocol service: AWS dispatches on X-Amz-Target and ignores any
		// Action parameter, so read only the header.
		if op := targetAction(req.Header.Get("X-Amz-Target")); op != "" {
			return op
		}
	case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
		// Query-protocol POST: AWS dispatches on the form-body Action and ignores
		// X-Amz-Target and the URL query, so read only the body — a ?Action= decoy
		// in the URL cannot mask the body's real Action.
		if a := formAction(contentType, body); a != "" {
			return a
		}
	default:
		// No protocol-identifying Content-Type: a query-protocol GET carries its
		// Action in the URL query (e.g. STS GetCallerIdentity).
		if a := req.URL.Query().Get("Action"); a != "" {
			return a
		}
	}

	return req.Method + " " + req.URL.Path
}

// targetAction returns the bare operation from an X-Amz-Target header
// ("DynamoDB_20120810.PutItem" -> "PutItem"), or "" when the header is empty.
func targetAction(target string) string {
	if target == "" {
		return ""
	}

	if i := strings.LastIndexByte(target, '.'); i >= 0 {
		return target[i+1:]
	}

	return target
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
