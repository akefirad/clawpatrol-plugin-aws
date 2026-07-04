package awssign_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akefirad/clawpatrol-plugin-aws/internal/awssign"
)

// Known-good SHA-256 hashes computed independently (printf … | shasum -a 256),
// not by re-running the implementation's hashing — so the assertions can't
// pass tautologically.
const (
	emptyBodySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	stsBodySHA256   = "2773842e9fb86ebb13ff1a59ce073407a3b41dd190d39cd9ce585a2cd8941996"
	stsBody         = `{"Action":"GetCallerIdentity","Version":"2011-06-15"}`
)

// placeholder is the identity the agent signs with (ADR 0001 D5): AKIA +
// account + padding. It must be gone from the re-signed request.
const (
	placeholderAKID  = "AKIA1234567890120000"
	placeholderToken = "PLACEHOLDER-SESSION-TOKEN"
)

// incomingRequest fakes an agent request as it arrives at the endpoint:
// placeholder-signed, with an X-Amz-Security-Token the re-sign must replace.
func incomingRequest(t *testing.T, host, body string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+host+"/", strings.NewReader(body))
	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential="+placeholderAKID+
			"/20200101/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef")
	req.Header.Set("X-Amz-Security-Token", placeholderToken)

	return req
}

func TestSignRequest_ReplacesPlaceholderWithSeededIdentity(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	const host = "sts.us-east-1.amazonaws.com"

	service, region := awssign.ParseServiceRegion(host) // service/region come from the host
	must.Equal("sts", service)
	must.Equal("us-east-1", region)

	seeded := aws.Credentials{
		AccessKeyID:     "ASIASEEDEDCREDS12345",
		SecretAccessKey: "seededsecretaccesskey0000000000000000000",
		SessionToken:    "SEEDED-SESSION-TOKEN",
	}

	body := []byte(stsBody)
	out, err := awssign.SignRequest(context.Background(), incomingRequest(t, host, stsBody), host, body, service, region, seeded)
	must.NoError(err)
	must.NotNil(out)

	authz := out.Header.Get("Authorization")
	must.NotEmpty(authz)
	// The seeded identity signs the request; the placeholder is gone.
	is.Contains(authz, "Credential="+seeded.AccessKeyID+"/")
	is.NotContains(authz, placeholderAKID)
	// Credential scope carries the service/region derived from the host.
	is.Contains(authz, "/"+region+"/"+service+"/aws4_request")

	// The agent's placeholder session token is replaced by the seeded one.
	is.Equal("SEEDED-SESSION-TOKEN", out.Header.Get("X-Amz-Security-Token"))

	// The payload hash header matches the body (independently known hash).
	is.Equal(stsBodySHA256, out.Header.Get("X-Amz-Content-Sha256"))

	// Upstream request targets the AWS host, not the agent's placeholder URL.
	is.Equal(host, out.Host)
	is.Empty(out.RequestURI)
}

func TestSignRequest_EmptyBodyAndNoSessionToken(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	const host = "iam.amazonaws.com" // global service

	service, region := awssign.ParseServiceRegion(host)
	must.Equal("iam", service)
	must.Equal("us-east-1", region) // global services sign as us-east-1 (D7)

	seeded := aws.Credentials{
		AccessKeyID:     "AKIASEEDEDLONGTERM01",
		SecretAccessKey: "seededsecretaccesskey0000000000000000000",
		// no SessionToken
	}

	out, err := awssign.SignRequest(context.Background(), incomingRequest(t, host, ""), host, nil, service, region, seeded)
	must.NoError(err)
	must.NotNil(out)

	authz := out.Header.Get("Authorization")
	is.Contains(authz, "Credential="+seeded.AccessKeyID+"/")
	is.Contains(authz, "/"+region+"/"+service+"/aws4_request")

	// No seeded session token => the header is absent (placeholder dropped).
	_, present := out.Header["X-Amz-Security-Token"]
	is.False(present)

	// Empty body's known SHA-256.
	is.Equal(emptyBodySHA256, out.Header.Get("X-Amz-Content-Sha256"))
}
