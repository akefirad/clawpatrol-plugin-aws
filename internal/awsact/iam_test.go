package awsact

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIAMAction_Determined(t *testing.T) {
	t.Parallel()

	cases := []struct {
		service string
		action  string
		want    string
	}{
		{service: "s3", action: "GetObject", want: "s3:GetObject"},
		{service: "s3", action: "PutObject", want: "s3:PutObject"},
		{service: "s3", action: "DeleteObject", want: "s3:DeleteObject"},
		{service: "s3", action: "ListObjects", want: "s3:ListBucket"},
		{service: "s3", action: "ListObjectsV2", want: "s3:ListBucket"},
		{service: "s3", action: "HeadObject", want: "s3:GetObject"},
		{service: "s3", action: "ListObjectVersions", want: "s3:ListBucketVersions"},
		{service: "s3", action: "ListBuckets", want: "s3:ListAllMyBuckets"},
		{service: "ec2", action: "DescribeInstances", want: "ec2:DescribeInstances"},
		{service: "dynamodb", action: "PutItem", want: "dynamodb:PutItem"},
		{service: "sts", action: "GetCallerIdentity", want: "sts:GetCallerIdentity"},
		{service: "monitoring", action: "PutMetricData", want: "cloudwatch:PutMetricData"},
	}

	for _, tc := range cases {
		t.Run(tc.service+":"+tc.action, func(t *testing.T) {
			t.Parallel()

			got, ok := IAMAction(tc.service, tc.action)
			assert.True(t, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIAMAction_Undeterminable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		service string
		action  string
	}{
		{name: "empty service", service: "", action: "PutItem"},
		{name: "empty action", service: "s3", action: ""},
		{name: "method-path fallback has a space", service: "s3", action: "GET /some/resource"},
		{name: "method-path fallback has a slash", service: "lambda", action: "POST /2015-03-31/functions"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := IAMAction(tc.service, tc.action)
			assert.False(t, ok, "undeterminable iam_action must be omitted, not guessed")
			assert.Empty(t, got)
		})
	}
}
