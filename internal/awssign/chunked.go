package awssign

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// continue100 is the interim response that tells an agent holding back an
// upload body (Expect: 100-continue) to go ahead and send it.
var continue100 = []byte("HTTP/1.1 100 Continue\r\n\r\n")

// IsChunked reports whether the request body is aws-chunked (S3 streaming
// uploads). It is signalled either by an "aws-chunked" Content-Encoding token
// or by the STREAMING-* marker AWS puts in X-Amz-Content-Sha256.
func IsChunked(h http.Header) bool {
	if containsToken(h.Get("Content-Encoding"), "aws-chunked") {
		return true
	}

	return strings.HasPrefix(strings.ToUpper(h.Get("X-Amz-Content-Sha256")), "STREAMING-")
}

// NormalizeChunked converts an aws-chunked request into a plain one so it
// re-signs cleanly: it decodes body to the raw payload, replaces req's body
// length with the decoded length, and strips the chunk-framing / checksum
// headers the from-scratch re-sign does not reproduce (which would otherwise
// make AWS reject the signature). A request that is not aws-chunked is returned
// untouched.
func NormalizeChunked(req *http.Request, body []byte) ([]byte, error) {
	if !IsChunked(req.Header) {
		return body, nil
	}

	raw, err := DecodeChunked(body)
	if err != nil {
		return nil, fmt.Errorf("decode aws-chunked body: %w", err)
	}

	stripChunkedHeaders(req.Header)

	req.ContentLength = int64(len(raw))
	req.Header.Set("Content-Length", strconv.Itoa(len(raw)))

	return raw, nil
}

// stripChunkedHeaders removes the headers that describe the aws-chunked
// framing but do not survive a from-scratch re-sign of the decoded payload:
// the aws-chunked Content-Encoding, the decoded-length hint, the STREAMING
// content hash (SignRequest recomputes X-Amz-Content-Sha256 over the raw
// body), and the per-chunk / trailing checksum headers.
func stripChunkedHeaders(h http.Header) {
	h.Del("X-Amz-Decoded-Content-Length")
	h.Del("X-Amz-Content-Sha256")
	h.Del("X-Amz-Trailer")

	for _, name := range headerNames(h) {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Amz-Checksum-") {
			h.Del(name)
		}
	}

	if enc := dropToken(h.Get("Content-Encoding"), "aws-chunked"); enc == "" {
		h.Del("Content-Encoding")
	} else {
		h.Set("Content-Encoding", enc)
	}
}

// DecodeChunked decodes an aws-chunked body into its raw payload. The wire
// format is a sequence of
//
//	<hex-size>[;chunk-signature=<hex>]\r\n<size bytes>\r\n
//
// chunks ending with a zero-size chunk, which may be followed by trailing
// (checksum) headers. Per-chunk signatures and trailers are discarded — only
// the data bytes matter, since the payload is re-signed from scratch.
func DecodeChunked(body []byte) ([]byte, error) {
	out := make([]byte, 0, len(body))

	for i := 0; ; {
		j := bytes.Index(body[i:], []byte("\r\n"))
		if j < 0 {
			return nil, errors.New("malformed aws-chunked body: no CRLF after chunk header")
		}

		header := body[i : i+j]
		i += j + 2

		// The chunk header is "<hex-size>[;chunk-signature=…]"; keep only the size.
		sizeField, _, _ := bytes.Cut(header, []byte{';'})

		size, err := strconv.ParseInt(string(bytes.TrimSpace(sizeField)), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("bad aws-chunked chunk size %q: %w", sizeField, err)
		}

		if size == 0 {
			return out, nil
		}

		if int64(i)+size > int64(len(body)) {
			return nil, fmt.Errorf("aws-chunked chunk size %d exceeds remaining body %d", size, len(body)-i)
		}

		out = append(out, body[i:i+int(size)]...)
		i += int(size)

		// Every data chunk is terminated by CRLF. Require it: silently tolerating a
		// missing terminator would reinterpret the following bytes as the next
		// chunk header, decoding a corrupt payload instead of failing.
		if i+2 > len(body) || body[i] != '\r' || body[i+1] != '\n' {
			return nil, errors.New("malformed aws-chunked body: missing CRLF after chunk data")
		}

		i += 2
	}
}

// Ack100Continue writes the 100 Continue interim response to w when the
// request carries Expect: 100-continue, so an agent that waits for the go
// ahead before streaming an upload body proceeds. It is a no-op otherwise.
func Ack100Continue(w io.Writer, h http.Header) error {
	if !strings.EqualFold(strings.TrimSpace(h.Get("Expect")), "100-continue") {
		return nil
	}

	if _, err := w.Write(continue100); err != nil {
		return fmt.Errorf("write 100 Continue: %w", err)
	}

	return nil
}

// headerNames snapshots the header keys so a caller can delete entries without
// mutating the map mid-range.
func headerNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}

	return names
}

// containsToken reports whether the comma-separated header value contains
// token (case-insensitive).
func containsToken(value, token string) bool {
	for part := range strings.SplitSeq(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}

	return false
}

// dropToken removes token from a comma-separated header value, returning the
// remaining tokens rejoined (empty when token was the only one).
func dropToken(value, token string) string {
	kept := make([]string, 0)

	for part := range strings.SplitSeq(value, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" || strings.EqualFold(trimmed, token) {
			continue
		}

		kept = append(kept, trimmed)
	}

	return strings.Join(kept, ", ")
}
