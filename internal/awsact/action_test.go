package awsact

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Reused S3 request paths (object key vs. bucket root).
const (
	s3ObjectKey  = "/bucket/key.txt"
	s3BucketPath = "/bucket"
)

// Request headers the action classifier reads.
const (
	headerContentType = "Content-Type"
	headerAmzTarget   = "X-Amz-Target"
)

// newRequest builds a request the way handleConn hands one to the parser:
// method, an absolute URL (so req.URL carries the path + raw query), and a
// host. headers is applied last.
func newRequest(t *testing.T, method, host, target string, headers map[string]string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), method, "https://"+host+target, nil)
	req.Host = host

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return req
}

func TestAction_S3REST(t *testing.T) {
	t.Parallel()

	const host = "s3.amazonaws.com"

	cases := []struct {
		name   string
		method string
		target string
		header map[string]string
		want   string
	}{
		{name: "get object", method: http.MethodGet, target: s3ObjectKey, want: "GetObject"},
		{name: "head object", method: http.MethodHead, target: s3ObjectKey, want: "HeadObject"},
		{name: "put object", method: http.MethodPut, target: s3ObjectKey, want: "PutObject"},
		{name: "delete object", method: http.MethodDelete, target: s3ObjectKey, want: "DeleteObject"},
		{name: "copy object", method: http.MethodPut, target: s3ObjectKey, header: map[string]string{"X-Amz-Copy-Source": "/other/src"}, want: "CopyObject"},
		{name: "list buckets", method: http.MethodGet, target: "/", want: "ListBuckets"},
		{name: "list objects v1", method: http.MethodGet, target: s3BucketPath, want: "ListObjects"},
		{name: "list objects v2", method: http.MethodGet, target: s3BucketPath + "?list-type=2", want: "ListObjectsV2"},
		{name: "head bucket", method: http.MethodHead, target: s3BucketPath, want: "HeadBucket"},
		{name: "create bucket", method: http.MethodPut, target: s3BucketPath, want: "CreateBucket"},
		{name: "delete bucket", method: http.MethodDelete, target: s3BucketPath, want: "DeleteBucket"},
		{name: "list object versions subresource", method: http.MethodGet, target: s3BucketPath + "?versions", want: "ListObjectVersions"},
		{name: "get bucket acl subresource", method: http.MethodGet, target: s3BucketPath + "?acl", want: "GetBucketAcl"},
		{name: "get object tagging subresource", method: http.MethodGet, target: s3ObjectKey + "?tagging", want: "GetObjectTagging"},
		{name: "multipart initiate", method: http.MethodPost, target: s3ObjectKey + "?uploads", want: "CreateMultipartUpload"},
		{name: "delete objects batch", method: http.MethodPost, target: s3BucketPath + "?delete", want: "DeleteObjects"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := newRequest(t, tc.method, host, tc.target, tc.header)
			assert.Equal(t, tc.want, Action(req, nil, "s3"))
		})
	}
}

// A multipart lifecycle write must win over a co-present read subresource: a
// POST carrying both ?uploadId and ?select is CompleteMultipartUpload (a write),
// not SelectObjectContent (a read).
func TestAction_S3MultipartBeatsSubresource(t *testing.T) {
	t.Parallel()

	req := newRequest(t, http.MethodPost, "s3.amazonaws.com", s3ObjectKey+"?uploadId=ABC&select", nil)

	assert.Equal(t, "CompleteMultipartUpload", Action(req, nil, "s3"))
}

// Two recognized subresource keys on one request must classify deterministically
// (stable across runs), not by randomized map order. Sorted precedence makes
// ?policy&acl resolve to acl.
func TestAction_S3MultipleSubresourcesDeterministic(t *testing.T) {
	t.Parallel()

	for range 50 {
		req := newRequest(t, http.MethodPut, "s3.amazonaws.com", s3BucketPath+"?policy&acl", nil)
		assert.Equal(t, "PutBucketAcl", Action(req, nil, "s3"))
	}
}

func TestAction_JSONProtocolTarget(t *testing.T) {
	t.Parallel()

	req := newRequest(t, http.MethodPost, "dynamodb.us-east-1.amazonaws.com", "/", map[string]string{
		headerContentType: "application/x-amz-json-1.0",
		headerAmzTarget:   "DynamoDB_20120810.PutItem",
	})

	assert.Equal(t, "PutItem", Action(req, nil, "dynamodb"))
}

// A JSON-protocol request must be classified from X-Amz-Target (the field AWS
// executes), ignoring a decoy ?Action= in the URL an agent adds to make a write
// look like a read.
func TestAction_JSONProtocolIgnoresQueryActionDecoy(t *testing.T) {
	t.Parallel()

	req := newRequest(t, http.MethodPost, "dynamodb.us-east-1.amazonaws.com", "/?Action=GetItem", map[string]string{
		headerContentType: "application/x-amz-json-1.0",
		headerAmzTarget:   "DynamoDB_20120810.DeleteItem",
	})

	assert.Equal(t, "DeleteItem", Action(req, nil, "dynamodb"))
}

// A query-protocol POST must be classified from the form-body Action (the field
// AWS executes), ignoring a spoofed X-Amz-Target header that would otherwise
// mask the real mutation as a read.
func TestAction_QueryProtocolIgnoresSpoofedTarget(t *testing.T) {
	t.Parallel()

	body := []byte("Action=TerminateInstances&InstanceId.1=i-0&Version=2016-11-15")
	req := newRequest(t, http.MethodPost, "ec2.eu-central-1.amazonaws.com", "/", map[string]string{
		headerContentType: "application/x-www-form-urlencoded",
		headerAmzTarget:   "x.DescribeInstances",
	})

	assert.Equal(t, "TerminateInstances", Action(req, body, "ec2"))
}

// A query-protocol POST must be classified from the form-body Action, ignoring a
// decoy ?Action= in the URL (AWS resolves the operation from the body it is
// sent, not the query string).
func TestAction_QueryProtocolIgnoresQueryActionDecoy(t *testing.T) {
	t.Parallel()

	body := []byte("Action=TerminateInstances&InstanceId.1=i-0&Version=2016-11-15")
	req := newRequest(t, http.MethodPost, "ec2.eu-central-1.amazonaws.com", "/?Action=DescribeInstances", map[string]string{
		headerContentType: "application/x-www-form-urlencoded",
	})

	assert.Equal(t, "TerminateInstances", Action(req, body, "ec2"))
}

// The protocol is chosen from the service, not the agent-supplied Content-Type:
// a query-protocol service (EC2) with a JSON Content-Type + spoofed X-Amz-Target
// is still classified from its form-body Action, so the write isn't masked.
func TestAction_QueryServiceIgnoresJSONContentTypeSpoof(t *testing.T) {
	t.Parallel()

	body := []byte("Action=TerminateInstances&InstanceId.1=i-0&Version=2016-11-15")
	req := newRequest(t, http.MethodPost, "ec2.eu-central-1.amazonaws.com", "/", map[string]string{
		headerContentType: "application/x-amz-json-1.0",
		headerAmzTarget:   "x.DescribeInstances",
	})

	assert.Equal(t, "TerminateInstances", Action(req, body, "ec2"))
}

// Symmetric: a JSON-protocol service (DynamoDB) with a form Content-Type + a
// decoy body/URL Action is still classified from X-Amz-Target.
func TestAction_JSONServiceIgnoresFormContentTypeSpoof(t *testing.T) {
	t.Parallel()

	body := []byte("Action=GetItem&Version=2012-08-10")
	req := newRequest(t, http.MethodPost, "dynamodb.us-east-1.amazonaws.com", "/", map[string]string{
		headerContentType: "application/x-www-form-urlencoded",
		headerAmzTarget:   "DynamoDB_20120810.DeleteItem",
	})

	assert.Equal(t, "DeleteItem", Action(req, body, "dynamodb"))
}

// An unknown service whose X-Amz-Target and Action parameter disagree is
// ambiguous (the dispatch field is unknown), so it fails closed to the mutation
// fallback rather than guessing a read.
func TestAction_UnknownServiceConflictFailsClosed(t *testing.T) {
	t.Parallel()

	req := newRequest(t, http.MethodGet, "newsvc.eu-central-1.amazonaws.com", "/?Action=DescribeThings", map[string]string{
		"X-Amz-Target": "New.DeleteThing",
	})

	assert.Equal(t, "GET /", Action(req, nil, "newsvc"))
}

// An unknown service carrying a single dispatch field is resolved best-effort.
func TestAction_UnknownServiceSingleFieldBestEffort(t *testing.T) {
	t.Parallel()

	req := newRequest(t, http.MethodPost, "newsvc.eu-central-1.amazonaws.com", "/", map[string]string{
		"X-Amz-Target": "New.DescribeThings",
	})

	assert.Equal(t, "DescribeThings", Action(req, nil, "newsvc"))
}

func TestAction_QueryProtocolFormAction(t *testing.T) {
	t.Parallel()

	body := []byte("Action=DescribeInstances&Version=2016-11-15")
	req := newRequest(t, http.MethodPost, "ec2.eu-central-1.amazonaws.com", "/", map[string]string{
		headerContentType: "application/x-www-form-urlencoded; charset=utf-8",
	})

	assert.Equal(t, "DescribeInstances", Action(req, body, "ec2"))
}

func TestAction_QueryProtocolURLAction(t *testing.T) {
	t.Parallel()

	req := newRequest(t, http.MethodGet, "sts.amazonaws.com", "/?Action=GetCallerIdentity&Version=2011-06-15", nil)

	assert.Equal(t, "GetCallerIdentity", Action(req, nil, "sts"))
}

func TestAction_FallbackMethodPath(t *testing.T) {
	t.Parallel()

	// An unknown service with no X-Amz-Target and no Action param: the verb is
	// unknowable, so it falls back to "METHOD path" (which matches no read
	// prefix and is gated as a mutation).
	req := newRequest(t, http.MethodGet, "unknownsvc.eu-central-1.amazonaws.com", "/some/resource", nil)

	assert.Equal(t, "GET /some/resource", Action(req, nil, "unknownsvc"))
}
