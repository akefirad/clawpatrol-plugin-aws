package awssign

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// regionFrankfurt is a representative non-default (non-global) region, used to
// prove the region is read from the host rather than falling back to us-east-1.
const regionFrankfurt = "eu-central-1"

func TestParseServiceRegion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		host        string
		wantService string
		wantRegion  string
	}{
		{
			name:        "global service signs us-east-1",
			host:        "iam.amazonaws.com",
			wantService: "iam",
			wantRegion:  defaultRegion,
		},
		{
			name:        "regional service",
			host:        "ec2.eu-central-1.amazonaws.com",
			wantService: "ec2",
			wantRegion:  regionFrankfurt,
		},
		{
			name:        "path-style s3 regional",
			host:        "s3.eu-central-1.amazonaws.com",
			wantService: "s3",
			wantRegion:  regionFrankfurt,
		},
		{
			name:        "region-less s3 signs us-east-1",
			host:        "s3.amazonaws.com",
			wantService: "s3",
			wantRegion:  defaultRegion,
		},
		{
			name:        "virtual-hosted s3 region-less",
			host:        "bucket.s3.amazonaws.com",
			wantService: "s3",
			wantRegion:  defaultRegion,
		},
		{
			name:        "virtual-hosted s3 regional",
			host:        "bucket.s3.us-east-1.amazonaws.com",
			wantService: "s3",
			wantRegion:  defaultRegion,
		},
		{
			name:        "dualstack s3",
			host:        "s3.dualstack.us-east-1.amazonaws.com",
			wantService: "s3",
			wantRegion:  defaultRegion,
		},
		{
			name:        "virtual-hosted dualstack s3",
			host:        "bucket.s3.dualstack.eu-central-1.amazonaws.com",
			wantService: "s3",
			wantRegion:  regionFrankfurt,
		},
		{
			name:        "bucket named s3 (virtual-hosted)",
			host:        "s3.s3.us-east-1.amazonaws.com",
			wantService: "s3",
			wantRegion:  defaultRegion,
		},
		{
			name:        "port suffix is stripped",
			host:        "ec2.eu-central-1.amazonaws.com:443",
			wantService: "ec2",
			wantRegion:  regionFrankfurt,
		},
		{
			name:        "virtual-hosted s3 with port",
			host:        "bucket.s3.us-east-1.amazonaws.com:443",
			wantService: "s3",
			wantRegion:  defaultRegion,
		},
		{
			name:        "trailing dot (rooted) host",
			host:        "sts.us-east-1.amazonaws.com.",
			wantService: "sts",
			wantRegion:  defaultRegion,
		},
		{
			name:        "uppercase host is normalized",
			host:        "STS.US-EAST-1.AMAZONAWS.COM",
			wantService: "sts",
			wantRegion:  defaultRegion,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			is := assert.New(t)

			service, region := ParseServiceRegion(tc.host)
			is.Equal(tc.wantService, service)
			is.Equal(tc.wantRegion, region)
		})
	}
}
