// Package awssign holds the stateless AWS request machinery the endpoint uses:
// deriving the signing service/region from the request host, decoding the
// target account from the SigV4 access-key id, and re-signing a request with
// freshly supplied credentials.
package awssign

import (
	"context"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// SignRequest builds a clean upstream request for host, signed with SigV4 from
// creds. It drops the agent's placeholder Authorization / X-Amz-Security-Token,
// sets X-Amz-Content-Sha256 to the hash of body, and signs for service/region
// (which the caller derives from host, see ParseServiceRegion).
//
// STUB: implemented in the seam-1 green step.
func SignRequest(
	_ context.Context,
	_ *http.Request,
	_ string,
	_ []byte,
	_, _ string,
	_ aws.Credentials,
) (*http.Request, error) {
	return nil, nil
}
