package awssign

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsChunked(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		h    http.Header
		want bool
	}{
		{
			name: "content-encoding token",
			h:    http.Header{"Content-Encoding": {"aws-chunked"}},
			want: true,
		},
		{
			name: "content-encoding token among others",
			h:    http.Header{"Content-Encoding": {"aws-chunked, gzip"}},
			want: true,
		},
		{
			name: "streaming content-sha256 marker",
			h:    http.Header{"X-Amz-Content-Sha256": {"STREAMING-AWS4-HMAC-SHA256-PAYLOAD"}},
			want: true,
		},
		{
			name: "plain request",
			h:    http.Header{"Content-Encoding": {"gzip"}, "X-Amz-Content-Sha256": {"abcdef"}},
			want: false,
		},
		{
			name: "no headers",
			h:    http.Header{},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, IsChunked(tc.h))
		})
	}
}

// chunk formats one aws-chunked data chunk: "<hex-size>;chunk-signature=…\r\n<data>\r\n".
func chunk(data string) string {
	return string(append([]byte(hexSize(len(data))+";chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n"+data), "\r\n"...))
}

func hexSize(n int) string {
	const digits = "0123456789abcdef"

	if n == 0 {
		return "0"
	}

	var b []byte

	for n > 0 {
		b = append([]byte{digits[n&0xf]}, b...)
		n >>= 4
	}

	return string(b)
}

func TestDecodeChunked(t *testing.T) {
	t.Parallel()

	// A payload streamed as two data chunks plus the terminating zero chunk.
	body := chunk("hello ") + chunk("world") +
		"0;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\r\n"

	raw, err := DecodeChunked([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(raw))
}

func TestDecodeChunked_UnsignedTrailer(t *testing.T) {
	t.Parallel()

	// The unsigned-trailer checksum variant: the zero chunk is followed by a
	// trailing checksum header, which is not part of the object content.
	body := chunk("payload") +
		"0\r\n" +
		"x-amz-checksum-crc32c:aXQ9Cw==\r\n\r\n"

	raw, err := DecodeChunked([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "payload", string(raw))
}

func TestDecodeChunked_Malformed(t *testing.T) {
	t.Parallel()

	_, err := DecodeChunked([]byte("zz;chunk-signature=bad\r\ndata\r\n"))
	assert.Error(t, err)
}

func TestDecodeChunked_MissingInterChunkCRLF(t *testing.T) {
	t.Parallel()

	// A data chunk not terminated by CRLF: "hello" runs straight into the "0"
	// zero-chunk header. Without the CRLF check this is silently reinterpreted as
	// the next chunk header, decoding a corrupt payload; it must be an error.
	body := "5;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n" +
		"hello" + // no trailing CRLF
		"0\r\n\r\n"

	_, err := DecodeChunked([]byte(body))
	assert.Error(t, err)
}

func TestDecodeChunked_RejectsMalformedSizeWithoutPanic(t *testing.T) {
	t.Parallel()

	// Attacker-controlled chunk sizes that used to slip past the bounds check and
	// panic at the slice (a per-connection DoS): a negative size, and a size so
	// large that i+size wraps negative. Both must be a clean error, never a panic.
	cases := []struct {
		name string
		body string
	}{
		{name: "negative size", body: "-1\r\ndata\r\n"},
		{name: "overflowing size", body: "7fffffffffffffff\r\ndata\r\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.NotPanics(t, func() {
				_, err := DecodeChunked([]byte(tc.body))
				assert.Error(t, err)
			})
		})
	}
}

func TestNormalizeChunked_DecodesAndStripsHeaders(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	body := chunk("payload") + "0\r\n\r\n"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, "https://s3.amazonaws.com/bucket/key", bytes.NewReader([]byte(body)))
	must.NoError(err)
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("X-Amz-Decoded-Content-Length", "7")
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	req.Header.Set("X-Amz-Checksum-Crc32c", "aXQ9Cw==")
	req.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32c")
	req.Header.Set("Content-Type", "text/plain")

	raw, err := NormalizeChunked(req, []byte(body))
	must.NoError(err)

	// The raw payload is recovered.
	is.Equal("payload", string(raw))

	// Content-Length reflects the decoded payload, on both the field and header.
	is.Equal(int64(len("payload")), req.ContentLength)
	is.Equal("7", req.Header.Get("Content-Length"))

	// The chunk-framing / checksum headers the re-sign won't reproduce are gone.
	is.Empty(req.Header.Get("Content-Encoding"))
	is.Empty(req.Header.Get("X-Amz-Decoded-Content-Length"))
	is.Empty(req.Header.Get("X-Amz-Content-Sha256"))
	is.Empty(req.Header.Get("X-Amz-Checksum-Crc32c"))
	is.Empty(req.Header.Get("X-Amz-Trailer"))

	// Unrelated headers are preserved.
	is.Equal("text/plain", req.Header.Get("Content-Type"))
}

func TestNormalizeChunked_PassesThroughPlainBody(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	plain := []byte(`{"Action":"GetCallerIdentity"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://sts.amazonaws.com/", bytes.NewReader(plain))
	must.NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	raw, err := NormalizeChunked(req, plain)
	must.NoError(err)

	// A non-chunked request is returned untouched.
	is.Equal(plain, raw)
	is.Equal("application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
}

func TestAck100Continue(t *testing.T) {
	t.Parallel()

	is := assert.New(t)
	must := require.New(t)

	var buf bytes.Buffer

	h := http.Header{"Expect": {"100-continue"}}
	must.NoError(Ack100Continue(&buf, h))
	is.Equal("HTTP/1.1 100 Continue\r\n\r\n", buf.String())

	// No Expect header: nothing is written.
	var none bytes.Buffer
	must.NoError(Ack100Continue(&none, http.Header{}))
	is.Empty(none.String())
}
