// Example clawpatrol gateway config for the AWS SSO plugin.
//
// It demonstrates AWS-action policy + human-in-the-loop over the `aws` facet:
// reads are allowed, S3 writes route to a human approver, and everything else
// is denied. Rules are gateway-owned CEL over the facet fields this plugin
// populates (ADR 0001 D8) — the plugin owns the facet, not the rule engine.
//
// Requires the fork gateway (the `aws_sso` OAuth flow, ADR 0001 D9). Build the
// plugin and point `source` at the binary, then:
//
//   clawpatrol gateway examples/gateway.hcl
//
// Facet fields available in `condition` (see internal/awsapi/facet.go):
//   aws.action      CloudTrail op name (audit verb) — always present
//   aws.iam_action  IAM action (e.g. s3:GetObject) — best-effort, may be absent
//   aws.service     AWS service (from the host)
//   aws.account     target account (decoded from the request's access-key id)
//   aws.region      signing region (from the host)
//   aws.resource    request path
//   aws.method      HTTP method — always present
// Result fields (reported after the response, shown in the request detail):
//   aws.status         HTTP code, or the AWS error code on a 4xx/5xx
//   aws.response_body  bounded sample of the response body

schema_version = 1

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

// Load this external plugin. Point source at the built binary (or a release
// artifact). The plugin declares its own egress (*.amazonaws.com:443) in its
// manifest; the gateway records the grant in clawpatrol.lock.hcl on first load.
plugin "aws" {
  source = "./clawpatrol-plugin-aws"
}

// Endpoints are split only on host/service (ADR 0001 D6): S3 gets its own
// endpoint so it can carry write-approval rules distinct from general AWS.
//
// NOTE: these host patterns cover the common global/virtual-host S3 form. A
// regional, path-style, or dualstack host (e.g. bucket.s3.eu-central-1.amazonaws.com,
// s3.dualstack.us-east-1.amazonaws.com) that must be gated as S3 needs its own
// entry here — otherwise it routes to aws_api.aws and the S3 write rules below
// don't apply. Add the regions/styles you actually use.
endpoint "aws_api" "s3" {
  hosts = [
    "*.s3.amazonaws.com", // virtual-host style (bucket.s3.amazonaws.com)
    "s3.amazonaws.com",   // path-style, global
  ]
}

endpoint "aws_api" "aws" {
  hosts = ["*.amazonaws.com"] // everything else (STS, EC2, DynamoDB, …)
}

// One SSO login (device flow, run by the fork gateway) serves every listed
// account across both endpoints (ADR 0001 D3). Roles are auto-discovered per
// account (single role per account) and placeholders are derived from the
// account id — no per-account config.
credential "aws_sso" "wp" {
  start_url = "https://my-org.awsapps.com/start"
  region    = "eu-central-1" // SSO / Identity Center region
  endpoints = [aws_api.aws, aws_api.s3]
  accounts  = ["111111111111", "222222222222"]
}

// A human approver for gated S3 writes (HITL). Evaluate holds the connection
// through this chain; on approval the plugin mints fresh credentials and
// forwards — a request approved after a delay is still signed with live creds
// (ADR 0001 request flow).
approver "human_approver" "s3-writes" {
  channel = "#aws-approvals"
}

// --- General AWS (aws_api.aws) -------------------------------------------

// Reads allow. iam_action is the right lever for reads (ADR 0001 D8): a missing
// mapping just over-denies, which fails closed = safe. Match IAM-style with
// startsWith or a regex; also allow the read-shaped HTTP methods so ops without
// an iam_action mapping (e.g. an unmapped Describe/List) still pass as reads.
rule "aws-reads" {
  endpoint  = aws_api.aws
  condition = "aws.iam_action.matches('^[a-z0-9-]+:(Get|List|Describe|Head|BatchGet).*') || aws.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

// Catch-all deny for general AWS: anything not matched above (writes, unknown
// verbs) is denied. Lower priority so the allow above wins when it matches.
rule "aws-default-deny" {
  endpoint  = aws_api.aws
  priority  = -100
  condition = "true"
  verdict   = "deny"
  reason    = "only read operations are allowed on general AWS; add a rule to permit this action"
}

// --- S3 (aws_api.s3) ------------------------------------------------------

// S3 reads allow (GET/HEAD object and bucket listings).
rule "s3-reads" {
  endpoint  = aws_api.s3
  condition = "aws.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

// S3 writes require human approval. Gate on the HTTP method (aws.method), NOT
// iam_action alone (ADR 0001 D8): iam_action is best-effort and absent for an
// unmapped mutating op, so an iam_action-only gate could be slipped by a write
// the plugin couldn't classify. PUT/POST/DELETE always carry a method.
rule "s3-writes-approve" {
  endpoint  = aws_api.s3
  condition = "aws.method in ['PUT', 'POST', 'DELETE', 'PATCH']"
  approve   = [human_approver.s3-writes]
}

// Catch-all deny for S3.
rule "s3-default-deny" {
  endpoint  = aws_api.s3
  priority  = -100
  condition = "true"
  verdict   = "deny"
  reason    = "S3 action not permitted by policy"
}

// --- Advisory: body-content rules -----------------------------------------
//
// Body-content conditions (e.g. aws.response_body.contains('...') or, if you
// extend the facet, a request-body field) are ADVISORY on this plugin, not a
// hard control: the plugin re-signs from scratch, so an UNSIGNED-PAYLOAD or an
// oversized/streaming body may not be fully available to the matcher
// (akefirad/clawpatrol#21). Treat any body-content rule as best-effort defense
// in depth; the IAM role remains the primary permission boundary (D8), with
// these CEL rules the secondary observability + HITL layer.

profile "default" {
  credentials = [aws_sso.wp]
}
