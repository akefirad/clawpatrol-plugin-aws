package awsapi

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// Result field names (the aws facet's ResultFields, reported via SetResult once
// the upstream response is known). Kept beside the request-facet fields so the
// declaration and the SetResult map never drift.
const (
	resultFieldStatus       = "status"
	resultFieldResponseBody = "response_body"
)

// errorPeekCap bounds how much of an error response body the plugin reads to
// extract the AWS error code. AWS error bodies (XML <Error> / JSON __type) are
// small; the code sits at the front. The remainder streams to the agent
// unbuffered, so a hostile oversized 4xx body can't be pulled into memory.
const errorPeekCap = 8 << 10 // 8 KiB

// responseSampleCap bounds the response-body sample the plugin tees for
// SetResult. It caps the plugin's own memory; the gateway caps again on its
// side (it owns body storage). A non-blocking tap: writes past the cap are
// dropped, never erroring the agent's copy.
const responseSampleCap = 16 << 10 // 16 KiB

// reportResponse writes the upstream response back to the agent and reports the
// outcome to the gateway via SetResult (ADR 0001 D8 result fields):
//
//   - status: the HTTP status code, or the AWS error code (e.g. AccessDenied)
//     on a 4xx/5xx when one is determinable from the headers/body.
//   - response_body: a bounded sample of the body, teed as the agent's copy is
//     written so the agent still receives the complete, unmodified response.
//
// Note (operator-facing): the response_body sample means up to responseSampleCap
// bytes of every upstream RESPONSE body are captured into the gateway's audit
// store — for example the leading bytes of an S3 GetObject payload, i.e. a
// sample of customer object data. This is intentional (it makes the response
// auditable), but operators should know their audit store holds a partial copy
// of response payloads.
//
// The agent's response is authoritative: a SetResult failure is best-effort
// (the agent already has its bytes) and never fails the request.
func reportResponse(ctx context.Context, conn resultConn, resp *http.Response) error {
	status := strconv.Itoa(resp.StatusCode)

	// On a 4xx/5xx, surface the AWS error code instead of the bare status. Peek a
	// bounded prefix of the body to extract it, then splice the prefix back in
	// front of the unread remainder so the agent still gets the whole body.
	if resp.StatusCode >= http.StatusBadRequest {
		prefix, rest := peekBody(resp.Body, errorPeekCap)
		if code, ok := errorCode(resp.Header, prefix); ok {
			status = code
		}

		resp.Body = readCloser{
			Reader: io.MultiReader(bytes.NewReader(prefix), rest),
			Closer: resp.Body,
		}
	}

	// Tee the body into a bounded sample as resp.Write drains it to the agent.
	// The agent's copy is unaffected; the tap only observes.
	tap := &boundedTap{limit: responseSampleCap}
	resp.Body = readCloser{
		Reader: io.TeeReader(resp.Body, tap),
		Closer: resp.Body,
	}

	if err := resp.Write(conn); err != nil {
		return err
	}

	// Best-effort: the response is already delivered, so a reporting failure must
	// not tear down the connection.
	_ = conn.SetResult(ctx, map[string]any{
		resultFieldStatus:       status,
		resultFieldResponseBody: pluginsdk.Stream(bytes.NewReader(tap.buf.Bytes())),
	})

	return nil
}

// peekBody reads up to limit bytes off r and returns them plus a reader for the
// unread remainder, without buffering the whole body — the caller splices the
// prefix back to reconstruct the full stream.
func peekBody(r io.Reader, limit int) (prefix []byte, rest io.Reader) {
	buf := make([]byte, limit)
	n, _ := io.ReadFull(r, buf)

	return buf[:n], r
}

// boundedTap is an io.Writer that keeps only the first limit bytes and silently
// drops the rest, always reporting a full write so an io.TeeReader copy driving
// it is never short-circuited or errored.
type boundedTap struct {
	buf   bytes.Buffer
	limit int
}

func (t *boundedTap) Write(p []byte) (int, error) {
	if room := t.limit - t.buf.Len(); room > 0 {
		if len(p) > room {
			t.buf.Write(p[:room])
		} else {
			t.buf.Write(p)
		}
	}

	return len(p), nil
}

// readCloser pairs a (possibly wrapped) reader with the original body's Closer
// so reassigning resp.Body keeps close semantics intact.
type readCloser struct {
	io.Reader
	io.Closer
}

// errorCode extracts the AWS error code from a failed response. The
// x-amzn-errortype header wins (JSON-protocol services set it); otherwise the
// body prefix is parsed as XML (S3/query <Code>) or JSON (__type / code).
// Returns false when none is determinable, so the caller falls back to the
// numeric HTTP status.
func errorCode(header http.Header, body []byte) (string, bool) {
	if v := header.Get("x-amzn-errortype"); v != "" {
		if code := normalizeErrorType(v); code != "" {
			return code, true
		}
	}

	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return "", false
	}

	if body[0] == '{' {
		return jsonErrorCode(body)
	}

	return xmlErrorCode(body)
}

// normalizeErrorType reduces an AWS error-type token to the bare code: it drops
// any "shape#" prefix (JSON __type / some headers) and any ":url" suffix
// (x-amzn-errortype) that AWS appends.
func normalizeErrorType(v string) string {
	if i := strings.LastIndexByte(v, '#'); i >= 0 {
		v = v[i+1:]
	}

	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[:i]
	}

	return strings.TrimSpace(v)
}

// xmlErrorCode returns the first <Code> element's text from an AWS XML error
// body (S3's <Error><Code> and query-protocol's <ErrorResponse><Error><Code>
// both nest a Code element).
func xmlErrorCode(body []byte) (string, bool) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}

		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Code" {
			continue
		}

		var code string
		if err := dec.DecodeElement(&code, &se); err != nil {
			return "", false
		}

		if code = strings.TrimSpace(code); code != "" {
			return code, true
		}

		return "", false
	}
}

// jsonErrorCode returns the error code from a JSON error body, checking the
// conventional keys in order (__type for AWS JSON/restjson, then code/Code).
func jsonErrorCode(body []byte) (string, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return "", false
	}

	for _, key := range []string{"__type", "code", "Code"} {
		raw, ok := fields[key]
		if !ok {
			continue
		}

		var val string
		if err := json.Unmarshal(raw, &val); err != nil {
			continue
		}

		if code := normalizeErrorType(val); code != "" {
			return code, true
		}
	}

	return "", false
}
