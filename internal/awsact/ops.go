package awsact

// S3 operation names (CloudTrail event names) that recur across the operation
// reconstruction table (s3.go) and the IAM-action overrides (iam.go).
const (
	opListBuckets        = "ListBuckets"
	opListObjects        = "ListObjects"
	opListObjectsV2      = "ListObjectsV2"
	opListObjectVersions = "ListObjectVersions"
	opHeadObject         = "HeadObject"
)

// Recurring IAM action strings for S3 operations whose IAM name diverges from
// the operation name (several operations map to the same IAM action).
const (
	iamS3GetObject  = "s3:GetObject"
	iamS3PutObject  = "s3:PutObject"
	iamS3ListBucket = "s3:ListBucket"
)
