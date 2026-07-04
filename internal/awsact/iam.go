package awsact

import "strings"

// IAMAction derives the IAM policy action (aws.iam_action) from the SigV4
// service and the parsed operation, e.g. ("ec2", "DescribeInstances") ->
// "ec2:DescribeInstances", ("s3", "ListObjectsV2") -> "s3:ListBucket".
//
// It is best-effort: "<prefix>:<Operation>" for the common case, with two
// curated divergences corrected — the IAM prefix when it differs from the host
// service label (monitoring -> cloudwatch, …) and S3's historically irregular
// action names (see s3IAMAction). ok is false — so the caller omits the facet
// field entirely rather than emitting a guess — when the operation could not
// be determined: an empty service/action, or a "METHOD path" fallback (which
// contains a space or slash). An absent iam_action makes any rule matching on
// it fail closed.
func IAMAction(service, action string) (iamAction string, ok bool) {
	if service == "" || action == "" || strings.ContainsAny(action, " /") {
		return "", false
	}

	if service == "s3" {
		if a, override := s3IAMAction[action]; override {
			return a, true
		}
	}

	return iamPrefix(service) + ":" + action, true
}

// iamPrefix maps a SigV4 service label to its IAM action prefix when the two
// differ; otherwise the service label is the prefix.
func iamPrefix(service string) string {
	if p, ok := iamPrefixOverride[service]; ok {
		return p
	}

	return service
}

// iamPrefixOverride lists the services whose IAM prefix differs from their
// SigV4/host service label.
var iamPrefixOverride = map[string]string{
	"monitoring":       "cloudwatch",
	"email":            "ses",
	"streams.dynamodb": "dynamodb",
}

// s3IAMAction overrides the S3 operation -> IAM action where they diverge.
// Operations absent here use the "s3:<Operation>" default, correct for the
// bulk of S3 (GetObject, PutObject, DeleteObject, GetBucketPolicy, …).
var s3IAMAction = map[string]string{
	opListBuckets:             "s3:ListAllMyBuckets",
	opListObjects:             iamS3ListBucket,
	opListObjectsV2:           iamS3ListBucket,
	"HeadBucket":              iamS3ListBucket,
	opListObjectVersions:      "s3:ListBucketVersions",
	"ListMultipartUploads":    "s3:ListBucketMultipartUploads",
	"ListParts":               "s3:ListMultipartUploadParts",
	opHeadObject:              iamS3GetObject,
	"SelectObjectContent":     iamS3GetObject,
	"CopyObject":              iamS3PutObject,
	"UploadPart":              iamS3PutObject,
	"UploadPartCopy":          iamS3PutObject,
	"CreateMultipartUpload":   iamS3PutObject,
	"CompleteMultipartUpload": iamS3PutObject,
	"DeleteObjects":           "s3:DeleteObject",
}
