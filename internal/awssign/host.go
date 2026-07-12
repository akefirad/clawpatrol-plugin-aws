package awssign

import (
	"net"
	"slices"
	"strings"
)

// defaultRegion is AWS's mandated signing region for region-less global
// services (IAM, Route53, the legacy global sts/s3 endpoints). It never
// touches regional traffic (ADR 0001 D7).
const defaultRegion = "us-east-1"

// ParseServiceRegion derives the SigV4 signing service and region from an AWS
// request host (ADR 0001 D7 — the region is never configured).
//
//	ec2.eu-central-1.amazonaws.com          -> ("ec2", "eu-central-1")
//	sts.us-east-1.amazonaws.com             -> ("sts", "us-east-1")
//	iam.amazonaws.com                       -> ("iam", "us-east-1")  // global
//	s3.eu-central-1.amazonaws.com           -> ("s3",  "eu-central-1") // path-style
//	s3.amazonaws.com                        -> ("s3",  "us-east-1")    // region-less
//	bucket.s3.amazonaws.com                 -> ("s3",  "us-east-1")    // virtual-hosted
//	bucket.s3.us-east-1.amazonaws.com       -> ("s3",  "us-east-1")    // regional v-hosted
//	s3.dualstack.us-east-1.amazonaws.com    -> ("s3",  "us-east-1")    // dualstack
//	bucket.s3.dualstack.eu-central-1...     -> ("s3",  "eu-central-1") // v-hosted dualstack
//
// S3 gets special handling because its "s3" service label is not always the
// leftmost one: a virtual-hosted request prepends the bucket
// (bucket.s3.us-east-1) and a dualstack endpoint inserts a modifier
// (s3.dualstack.us-east-1). A naive labels[0]/labels[1] read misparses both —
// e.g. bucket.s3.us-east-1 would decode as service="bucket", region="s3". We
// locate the "s3" label wherever it sits and read the region from the first
// non-"dualstack" label after it (region-less S3 signs the us-east-1 default).
func ParseServiceRegion(host string) (service, region string) {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	host = strings.TrimSuffix(strings.TrimSuffix(host, "."), ".amazonaws.com")

	labels := strings.Split(host, ".")

	if i := s3LabelIndex(labels); i >= 0 {
		region = defaultRegion

		for _, label := range labels[i+1:] {
			if label == "dualstack" {
				continue
			}

			region = label

			break
		}

		return "s3", region
	}

	service = labels[0]

	region = defaultRegion
	if len(labels) >= 2 && labels[1] != "" {
		region = labels[1]
	}

	return service, region
}

// s3LabelIndex returns the index of S3's "s3" service label in the host labels,
// or -1 when the host is not S3. It scans from the right so a bucket literally
// named "s3" (virtual-hosted as s3.s3.<region>.amazonaws.com) resolves to the
// service label rather than the bucket. This agrees with awsact.s3BucketInHost,
// which classifies a host as S3 by the same "s3" service label — the two must
// stay in step so the facet's service/region and the S3 operation
// reconstruction never disagree on which host is S3.
func s3LabelIndex(labels []string) int {
	for i, label := range slices.Backward(labels) {
		if label == "s3" {
			return i
		}
	}

	return -1
}
