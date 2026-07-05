package awsapi

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// errorTypeHeader is the canonical form of the x-amzn-errortype header AWS
// JSON-protocol services set the error code in.
const errorTypeHeader = "X-Amzn-Errortype"

// TestResponseCarriesSecret verifies the secret-returning (service, action)
// pairs whose response body is withheld from the audit store, and that sibling
// non-secret reads on the same services are still sampled.
func TestResponseCarriesSecret(t *testing.T) {
	t.Parallel()

	cases := []struct {
		service string
		action  string
		want    bool
	}{
		{"secretsmanager", "GetSecretValue", true},
		{"secretsmanager", "DescribeSecret", false},
		{"ssm", "GetParameter", true},
		{"ssm", "GetParameters", true},
		{"ssm", "GetParametersByPath", true},
		{"ssm", "DescribeParameters", false},
		{"sts", "AssumeRole", true},
		{"sts", "AssumeRoleWithWebIdentity", true},
		{"sts", "GetSessionToken", true},
		{"sts", "GetCallerIdentity", false},
		{"s3", "GetObject", false},
		{"dynamodb", "GetItem", false},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.want, responseCarriesSecret(tc.service, tc.action), "%s/%s", tc.service, tc.action)
	}
}

// TestErrorCode covers the representative shapes AWS surfaces an error code in:
// the x-amzn-errortype header (bare, shape-prefixed, URL-suffixed), an S3/query
// XML <Code>, and a JSON __type / code. The header wins over the body, and a
// body with no code yields no match so the caller falls back to the HTTP status.
func TestErrorCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header http.Header
		body   string
		want   string
		ok     bool
	}{
		{
			name:   "header bare",
			header: http.Header{errorTypeHeader: []string{"AccessDeniedException"}},
			want:   "AccessDeniedException",
			ok:     true,
		},
		{
			name:   "header url suffix stripped",
			header: http.Header{errorTypeHeader: []string{"ThrottlingException:http://internal.amazon.com/coral/com.amazon.coral.availability/"}},
			want:   "ThrottlingException",
			ok:     true,
		},
		{
			name:   "header shape prefix stripped",
			header: http.Header{errorTypeHeader: []string{"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException"}},
			want:   "ConditionalCheckFailedException",
			ok:     true,
		},
		{
			name:   "header wins over body",
			header: http.Header{errorTypeHeader: []string{"AccessDenied"}},
			body:   `<Error><Code>NoSuchKey</Code></Error>`,
			want:   "AccessDenied",
			ok:     true,
		},
		{
			name: "s3 xml code",
			body: `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`,
			want: "NoSuchBucket",
			ok:   true,
		},
		{
			name: "query xml nested errorresponse",
			body: `<?xml version="1.0"?><ErrorResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><Error><Type>Sender</Type><Code>UnauthorizedOperation</Code><Message>You are not authorized</Message></Error><RequestID>abc</RequestID></ErrorResponse>`,
			want: "UnauthorizedOperation",
			ok:   true,
		},
		{
			name: "json __type shape stripped",
			body: `{"__type":"com.amazon.coral.service#AccessDeniedException","message":"denied"}`,
			want: "AccessDeniedException",
			ok:   true,
		},
		{
			name: "json code",
			body: `{"code":"ExpiredTokenException","message":"The security token included in the request is expired"}`,
			want: "ExpiredTokenException",
			ok:   true,
		},
		{
			name: "json message only no code",
			body: `{"message":"Something went wrong"}`,
			ok:   false,
		},
		{
			name: "plain text no code",
			body: "Internal Server Error",
			ok:   false,
		},
		{
			name: "empty body no header",
			ok:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := errorCode(tc.header, []byte(tc.body))
			assert.Equal(t, tc.ok, ok)

			if tc.ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}
