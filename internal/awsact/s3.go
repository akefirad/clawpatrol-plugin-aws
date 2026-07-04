package awsact

import (
	"net/http"
	"net/url"
	"strings"
)

// s3Level classifies which S3 entity a request addresses.
type s3Level int

const (
	s3Service s3Level = iota // the account root: GET / -> ListBuckets
	s3Bucket                 // a bucket: GET /bucket -> ListObjects
	s3Object                 // a key within a bucket: GET /bucket/key -> GetObject
)

// s3Operation reconstructs the S3 API operation name (the CloudTrail
// eventName) from the request, since S3 is REST and never carries an operation
// on the wire. It handles both addressing styles: path-style
// ("s3.amazonaws.com/bucket/key" — bucket is the first path segment) and
// virtual-host-style ("bucket.s3.amazonaws.com/key" — bucket is in the host,
// so the whole path is the key). A recognized subresource query parameter
// (?acl, ?versions, ?tagging, …) refines the operation; otherwise the
// method+level default applies.
func s3Operation(req *http.Request) string {
	q := req.URL.Query()
	method := strings.ToUpper(req.Method)

	switch s3Target(req.Host, req.URL.Path) {
	case s3Service:
		if method == http.MethodGet {
			return opListBuckets
		}
	case s3Bucket:
		if op := s3BucketOp(q, method); op != "" {
			return op
		}
	case s3Object:
		if op := s3ObjectOp(req, q, method); op != "" {
			return op
		}
	}

	// Unknown method for the addressed level: keep it operation-shaped but
	// unmistakably non-standard so it can never match a read prefix.
	return method + " " + req.URL.Path
}

// s3BucketOp resolves a bucket-addressed operation, or "" for a method with no
// recognized bucket operation.
func s3BucketOp(q url.Values, method string) string {
	if op := subresourceOp(s3BucketSubresource, q, method); op != "" {
		return op
	}

	switch method {
	case http.MethodGet:
		if q.Get("list-type") == "2" {
			return opListObjectsV2
		}

		return opListObjects
	case http.MethodHead:
		return "HeadBucket"
	case http.MethodPut:
		return "CreateBucket"
	case http.MethodDelete:
		return "DeleteBucket"
	}

	return ""
}

// s3ObjectOp resolves an object-addressed operation (including the multipart
// lifecycle), or "" for a method with no recognized object operation.
func s3ObjectOp(req *http.Request, q url.Values, method string) string {
	if op := subresourceOp(s3ObjectSubresource, q, method); op != "" {
		return op
	}

	if _, initiating := q["uploads"]; initiating && method == http.MethodPost {
		return "CreateMultipartUpload"
	}

	if op := s3MultipartOp(req, q, method); op != "" {
		return op
	}

	switch method {
	case http.MethodGet:
		return "GetObject"
	case http.MethodHead:
		return opHeadObject
	case http.MethodPut:
		if req.Header.Get("X-Amz-Copy-Source") != "" {
			return "CopyObject"
		}

		return "PutObject"
	case http.MethodDelete:
		return "DeleteObject"
	}

	return ""
}

// s3MultipartOp resolves the multipart-upload lifecycle operations that key on
// an uploadId query parameter, or "" when the request is not one of them.
func s3MultipartOp(req *http.Request, q url.Values, method string) string {
	if q.Get("uploadId") == "" {
		return ""
	}

	switch method {
	case http.MethodPut:
		if req.Header.Get("X-Amz-Copy-Source") != "" {
			return "UploadPartCopy"
		}

		return "UploadPart"
	case http.MethodPost:
		return "CompleteMultipartUpload"
	case http.MethodDelete:
		return "AbortMultipartUpload"
	case http.MethodGet:
		return "ListParts"
	}

	return ""
}

// s3Target classifies the request as service/bucket/object addressing, using
// the host to tell path-style from virtual-host-style.
func s3Target(host, path string) s3Level {
	trimmed := strings.Trim(path, "/")

	if s3BucketInHost(host) {
		if trimmed == "" {
			return s3Bucket
		}

		return s3Object
	}

	if trimmed == "" {
		return s3Service
	}

	if bucket, key, ok := strings.Cut(trimmed, "/"); ok && bucket != "" && key != "" {
		return s3Object
	}

	return s3Bucket
}

// s3BucketInHost reports whether the bucket is encoded in the host
// (virtual-host-style). A path-style host's leftmost label is always the "s3"
// service label (s3, s3-fips, s3.dualstack, …); a virtual-host bucket prepends
// a label that is not, e.g. "mybucket.s3.us-east-1.amazonaws.com".
func s3BucketInHost(host string) bool {
	const suffix = ".amazonaws.com"

	host = strings.ToLower(host)
	if !strings.HasSuffix(host, suffix) {
		return false
	}

	first, _, _ := strings.Cut(strings.TrimSuffix(host, suffix), ".")

	return first != "" && !strings.HasPrefix(first, "s3")
}

// subresourceOp returns the operation for the first recognized subresource
// query key present for this method, or "" when none match.
func subresourceOp(table map[string]map[string]string, q url.Values, method string) string {
	for key, byMethod := range table {
		if _, present := q[key]; !present {
			continue
		}

		if op, ok := byMethod[method]; ok {
			return op
		}
	}

	return ""
}

// s3BucketSubresource maps a bucket-level subresource query key to the
// operation per HTTP method. Curated for the common configuration and listing
// operations; anything absent falls through to the method default.
var s3BucketSubresource = map[string]map[string]string{
	"acl":               {http.MethodGet: "GetBucketAcl", http.MethodPut: "PutBucketAcl"},
	"policy":            {http.MethodGet: "GetBucketPolicy", http.MethodPut: "PutBucketPolicy", http.MethodDelete: "DeleteBucketPolicy"},
	"tagging":           {http.MethodGet: "GetBucketTagging", http.MethodPut: "PutBucketTagging", http.MethodDelete: "DeleteBucketTagging"},
	"versioning":        {http.MethodGet: "GetBucketVersioning", http.MethodPut: "PutBucketVersioning"},
	"versions":          {http.MethodGet: opListObjectVersions},
	"location":          {http.MethodGet: "GetBucketLocation"},
	"cors":              {http.MethodGet: "GetBucketCors", http.MethodPut: "PutBucketCors", http.MethodDelete: "DeleteBucketCors"},
	"encryption":        {http.MethodGet: "GetBucketEncryption", http.MethodPut: "PutBucketEncryption", http.MethodDelete: "DeleteBucketEncryption"},
	"lifecycle":         {http.MethodGet: "GetBucketLifecycleConfiguration", http.MethodPut: "PutBucketLifecycleConfiguration", http.MethodDelete: "DeleteBucketLifecycle"},
	"replication":       {http.MethodGet: "GetBucketReplication", http.MethodPut: "PutBucketReplication", http.MethodDelete: "DeleteBucketReplication"},
	"notification":      {http.MethodGet: "GetBucketNotificationConfiguration", http.MethodPut: "PutBucketNotificationConfiguration"},
	"publicAccessBlock": {http.MethodGet: "GetPublicAccessBlock", http.MethodPut: "PutPublicAccessBlock", http.MethodDelete: "DeletePublicAccessBlock"},
	"uploads":           {http.MethodGet: "ListMultipartUploads"},
	"delete":            {http.MethodPost: "DeleteObjects"},
}

// s3ObjectSubresource maps an object-level subresource query key to the
// operation per HTTP method.
var s3ObjectSubresource = map[string]map[string]string{
	"acl":        {http.MethodGet: "GetObjectAcl", http.MethodPut: "PutObjectAcl"},
	"tagging":    {http.MethodGet: "GetObjectTagging", http.MethodPut: "PutObjectTagging", http.MethodDelete: "DeleteObjectTagging"},
	"retention":  {http.MethodGet: "GetObjectRetention", http.MethodPut: "PutObjectRetention"},
	"legal-hold": {http.MethodGet: "GetObjectLegalHold", http.MethodPut: "PutObjectLegalHold"},
	"attributes": {http.MethodGet: "GetObjectAttributes"},
	"restore":    {http.MethodPost: "RestoreObject"},
	"select":     {http.MethodPost: "SelectObjectContent"},
}
