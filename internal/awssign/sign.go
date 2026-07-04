// Package awssign holds the stateless AWS request machinery the endpoint uses:
// deriving the signing service/region from the request host, decoding the
// target account from the SigV4 access-key id, and re-signing a request with
// freshly supplied credentials.
package awssign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// SignRequest builds a clean upstream request for host, signed with SigV4 from
// creds. It drops the agent's placeholder Authorization / X-Amz-Security-Token,
// sets X-Amz-Content-Sha256 to the hash of body, and signs for service/region
// (which the caller derives from host, see ParseServiceRegion).
//
// The returned request carries the seeded identity: SignHTTP writes the
// Authorization header (Credential=<seeded AKID>/…) and, when creds has a
// session token, X-Amz-Security-Token; with no session token that header stays
// absent.
func SignRequest(
	ctx context.Context,
	req *http.Request,
	host string,
	body []byte,
	service, region string,
	creds aws.Credentials,
) (*http.Request, error) {
	if req.URL == nil {
		return nil, errors.New("request has no url")
	}

	out := req.Clone(ctx)
	out.RequestURI = ""
	out.URL.Scheme = "https"
	out.URL.Host = host
	out.Host = host

	// Drop the agent's placeholder signing material; we re-sign from scratch.
	out.Header.Del("Authorization")
	out.Header.Del("X-Amz-Security-Token")
	out.Header.Del("X-Amz-Date")

	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	out.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	out.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signer := v4.NewSigner()
	if err := signer.SignHTTP(ctx, creds, out, payloadHash, service, region, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("sigv4 sign %s/%s: %w", service, region, err)
	}

	return out, nil
}
