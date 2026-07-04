package awssign

import "strings"

// CredentialAKID extracts the access-key id from a SigV4 Authorization header,
// i.e. the token before the first '/' of the Credential= element:
//
//	AWS4-HMAC-SHA256 Credential=AKIA.../20260704/us-east-1/sts/aws4_request, ...
//
// Returns false when the header carries no Credential= element.
func CredentialAKID(authorization string) (string, bool) {
	const key = "Credential="
	i := strings.Index(authorization, key)
	if i < 0 {
		return "", false
	}
	rest := authorization[i+len(key):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j], true
	}
	return "", false
}

// AccountFromAKID decodes the 12-digit AWS account from an access-key id by
// returning its first run of 12 consecutive digits (ADR 0001 D5). The default
// placeholder is "AKIA" + account + padding, so "AKIA1234567890120000" decodes
// to "123456789012". Returns false when no 12-digit run is present.
func AccountFromAKID(akid string) (string, bool) {
	run := make([]byte, 0, 12)
	for i := 0; i < len(akid); i++ {
		c := akid[i]
		if c >= '0' && c <= '9' {
			run = append(run, c)
			if len(run) == 12 {
				return string(run), true
			}
			continue
		}
		run = run[:0]
	}
	return "", false
}
