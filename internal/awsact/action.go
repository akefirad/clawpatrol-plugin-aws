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
//   - JSON-protocol services (DynamoDB, Kinesis, CloudWatch Logs, …) carry the
//     operation in X-Amz-Target ("DynamoDB_20120810.PutItem" -> "PutItem").
//   - Query-protocol services (EC2, IAM, RDS, STS, SNS, …) carry an Action
//     parameter, form-encoded in the body for POST or in the URL query for GET
//     ("DescribeInstances").
//   - Otherwise the verb is unknowable and it falls back to "METHOD path",
//     which matches no read prefix and is therefore gated as a mutation.
//
// The wire protocol is selected from the service, not the request's
// Content-Type. AWS dispatches by service — EC2/IAM/RDS/STS/… are always query
// protocol and execute the Action parameter (ignoring X-Amz-Target), while
// DynamoDB/Kinesis/… are always JSON and execute X-Amz-Target (ignoring the
// Action parameter) — regardless of the Content-Type the client sent. Keying off
// the agent-controlled Content-Type (or trusting whichever slot the agent filled)
// is a parser differential: an agent could send a JSON Content-Type +
// X-Amz-Target=…DescribeInstances with a body Action=TerminateInstances to EC2
// and have the write classified as a read. So the operation is read from the
// field the routed *service* actually executes.
//
// For a service not in the protocol table the field AWS honors is unknown, so
// the classifier fails closed on ambiguity: if both X-Amz-Target and an Action
// parameter are present and disagree, it returns the "METHOD path" mutation
// fallback rather than guess; otherwise it uses whichever single field is
// present (best-effort).
//
// body is the already-read request body; service is the SigV4 signing name.
func Action(req *http.Request, body []byte, service string) string {
	if service == "s3" {
		return s3Operation(req)
	}

	switch serviceProtocol[service] {
	case protocolJSON:
		// AWS dispatches on X-Amz-Target and ignores any Action parameter.
		if op := targetAction(req.Header.Get("X-Amz-Target")); op != "" {
			return op
		}
	case protocolQuery:
		// AWS dispatches on the Action parameter and ignores X-Amz-Target, so a
		// spoofed X-Amz-Target cannot mask it. The parameter is form-encoded in the
		// body for POST and in the URL query otherwise — read where AWS reads it.
		if a := queryAction(req, body); a != "" {
			return a
		}
	case protocolUnknown:
		// Unknown service: fail closed on a conflicting X-Amz-Target vs. Action,
		// otherwise use whichever single field the request carries.
		if a := ambiguousAction(req, body); a != "" {
			return a
		}
	}

	return req.Method + " " + req.URL.Path
}

// serviceProtocol maps a SigV4 signing name to the wire protocol AWS uses for
// it, so the classifier reads the operation from the field the service
// dispatches on rather than one the agent can steer via Content-Type. S3 (REST)
// is handled separately in Action; services absent here are resolved
// best-effort with a conflict guard (see ambiguousAction). Not exhaustive — the
// security-relevant common services are covered; add more as needed.
var serviceProtocol = map[string]awsProtocol{
	// Query protocol (Action parameter).
	"ec2":                  protocolQuery,
	"iam":                  protocolQuery,
	"sts":                  protocolQuery,
	"rds":                  protocolQuery,
	"sns":                  protocolQuery,
	"elasticloadbalancing": protocolQuery,
	"autoscaling":          protocolQuery,
	"cloudformation":       protocolQuery,
	"monitoring":           protocolQuery, // cloudwatch
	"email":                protocolQuery, // ses
	"elasticache":          protocolQuery,
	"redshift":             protocolQuery,
	"elasticbeanstalk":     protocolQuery,
	"sdb":                  protocolQuery,

	// JSON protocol (X-Amz-Target).
	"dynamodb":         protocolJSON,
	"streams.dynamodb": protocolJSON,
	"kinesis":          protocolJSON,
	"firehose":         protocolJSON,
	"logs":             protocolJSON, // cloudwatch logs
	"events":           protocolJSON, // eventbridge
	"secretsmanager":   protocolJSON,
	"ssm":              protocolJSON,
	"ecr":              protocolJSON,
	"ecs":              protocolJSON,
	"sqs":              protocolJSON, // modern SQS is AWS JSON
	"kms":              protocolJSON,
	"cognito-identity": protocolJSON,
	"cognito-idp":      protocolJSON,
	"swf":              protocolJSON,
	"states":           protocolJSON, // step functions
}

// awsProtocol is how a service carries the operation on the wire.
type awsProtocol int

const (
	protocolUnknown awsProtocol = iota // service not in serviceProtocol
	protocolQuery                      // Action parameter (EC2-style query)
	protocolJSON                       // X-Amz-Target header (AWS JSON)
)

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

// queryAction returns a query-protocol request's Action, read where AWS reads
// it: the form-encoded body for a POST, the URL query otherwise. The body is
// parsed regardless of Content-Type, since AWS parses a query-protocol POST body
// as form parameters whatever header the client sent.
func queryAction(req *http.Request, body []byte) string {
	if req.Method == http.MethodPost {
		return bodyAction(body)
	}

	return req.URL.Query().Get("Action")
}

// bodyAction returns the Action field of a form-encoded body, or "" when it is
// absent or the body is not form-encoded.
func bodyAction(body []byte) string {
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return ""
	}

	return vals.Get("Action")
}

// ambiguousAction resolves the operation for a service of unknown protocol. It
// fails closed (returns "") when both an X-Amz-Target and an Action parameter
// are present but name different operations — the request is ambiguous and the
// dispatch field is unknown — and otherwise returns whichever single field is
// present.
func ambiguousAction(req *http.Request, body []byte) string {
	target := targetAction(req.Header.Get("X-Amz-Target"))
	query := queryAction(req, body)

	switch {
	case target != "" && query != "" && !strings.EqualFold(target, query):
		return ""
	case target != "":
		return target
	default:
		return query
	}
}
