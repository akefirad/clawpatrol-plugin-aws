package awssign_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
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

// TestSignRequest_S3DisablesURIPathDoubleEscaping proves S3 requests are signed
// without re-escaping the canonical URI path. It signs an S3 key holding
// characters the SDK's default escaping would double-encode and compares against
// an independent SigV4 signing of the identical request with default escaping ON
// (at the exact timestamp SignRequest used, so only the escaping differs): the
// signatures must diverge for the special-char key, and match for an
// unreserved-char key (the control that proves the divergence is the escaping,
// not the harness).
func TestSignRequest_S3DisablesURIPathDoubleEscaping(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	const (
		host   = "bucket.s3.us-east-1.amazonaws.com"
		region = "us-east-1"
	)

	seeded := aws.Credentials{
		AccessKeyID:     "ASIASEEDEDCREDS12345",
		SecretAccessKey: "seededsecretaccesskey0000000000000000000",
		SessionToken:    "SEEDED-SESSION-TOKEN",
	}

	// sign returns (SignRequest's S3 signature, an independent default-escaping
	// signature of the same request) for an object key.
	sign := func(key string) (s3Sig, defaultSig string) {
		body := []byte("data")

		out, err := awssign.SignRequest(context.Background(), s3PutRequest(t, host, key), host, body, "s3", region, seeded)
		must.NoError(err)

		tm, err := time.Parse("20060102T150405Z", out.Header.Get("X-Amz-Date"))
		must.NoError(err)

		// Mirror SignRequest's request prep, then sign with the SDK default (path
		// escaping ON) at the same timestamp.
		ref := s3PutRequest(t, host, key)
		ref.URL.Scheme = "https"
		ref.URL.Host = host
		ref.Host = host
		ref.Body = io.NopCloser(bytes.NewReader(body))
		ref.ContentLength = int64(len(body))

		sum := sha256.Sum256(body)
		payloadHash := hex.EncodeToString(sum[:])
		ref.Header.Set("X-Amz-Content-Sha256", payloadHash)

		must.NoError(v4.NewSigner().SignHTTP(context.Background(), seeded, ref, payloadHash, "s3", region, tm))

		return signatureOf(out.Header.Get("Authorization")), signatureOf(ref.Header.Get("Authorization"))
	}

	s3Sig, defSig := sign("/bucket/my file+name.txt")
	is.NotEqual(defSig, s3Sig, "S3 must sign without re-escaping the path (else SignatureDoesNotMatch)")

	plainS3, plainDef := sign("/bucket/plainkey.txt")
	is.Equal(plainDef, plainS3, "an unreserved-char key escapes to itself either way")
}

// s3PutRequest builds a placeholder-signed S3 PUT for key, setting the path
// directly so a space/reserved character survives into req.URL.Path.
func s3PutRequest(t *testing.T, host, key string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "https://"+host+"/", strings.NewReader(""))
	req.URL.Path = key
	req.URL.RawPath = ""
	req.Host = host

	return req
}

// signatureOf extracts the hex Signature from a SigV4 Authorization header.
func signatureOf(authz string) string {
	const marker = "Signature="
	if i := strings.LastIndex(authz, marker); i >= 0 {
		return authz[i+len(marker):]
	}

	return ""
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
