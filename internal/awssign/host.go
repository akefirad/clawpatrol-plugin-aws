package awssign

import (
	"net"
	"strings"
)

// defaultRegion is AWS's mandated signing region for region-less global
// services (IAM, Route53, the legacy global sts/s3 endpoints). It never
// touches regional traffic (ADR 0001 D7).
const defaultRegion = "us-east-1"

// ParseServiceRegion derives the SigV4 signing service and region from an AWS
// request host (ADR 0001 D7 — the region is never configured).
//
//	ec2.eu-central-1.amazonaws.com -> ("ec2", "eu-central-1")
//	sts.us-east-1.amazonaws.com    -> ("sts", "us-east-1")
//	iam.amazonaws.com              -> ("iam", "us-east-1")  // global
//
// Virtual-hosted / bucket-style S3 hosts get their own endpoint in a later
// slice; this first cut handles the common <service>.<region>.amazonaws.com
// and global <service>.amazonaws.com shapes.
func ParseServiceRegion(host string) (service, region string) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimSuffix(host, "."), ".amazonaws.com")

	labels := strings.Split(host, ".")
	service = labels[0]
	region = defaultRegion
	if len(labels) >= 2 && labels[1] != "" {
		region = labels[1]
	}
	return service, region
}
