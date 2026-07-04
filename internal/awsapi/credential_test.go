package awsapi

import (
	"encoding/json"
	"testing"

	"github.com/denoland/clawpatrol/pluginsdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testStartURL = "https://acme.awsapps.com/start"

// validCfg builds a well-formed aws_sso body varying only the account
// allowlist, so tests exercise validateAccounts without repeating the boilerplate.
func validCfg(accounts []string) map[string]any {
	return map[string]any{
		"start_url": testStartURL,
		"region":    testSSORegion,
		"accounts":  accounts,
	}
}

// buildFrom decodes cfg through the credential's Build callback, mirroring how
// the gateway invokes it at config-load time.
func buildFrom(t *testing.T, cfg map[string]any) (any, error) {
	t.Helper()

	body, err := json.Marshal(cfg)
	require.NoError(t, err)

	return buildCredential(pluginsdk.BuildRequest{
		Kind:       "credential",
		TypeName:   CredentialTypeName,
		ConfigJSON: body,
	})
}

func TestBuildCredential_AcceptsAccountAllowlist(t *testing.T) {
	t.Parallel()

	res, err := buildFrom(t, validCfg([]string{"111111111111", "222222222222"}))
	require.NoError(t, err)

	built, ok := res.(pluginsdk.CredentialBuildResult)
	require.True(t, ok, "build returns a CredentialBuildResult")

	cfg, ok := built.Canonical.(ssoConfig)
	require.True(t, ok, "canonical config is an ssoConfig")
	assert.Equal(t, []string{"111111111111", "222222222222"}, cfg.Accounts)

	// The Connect-card OAuth wiring is preserved (ADR 0001 D9).
	require.NotNil(t, built.Metadata.OAuth)
	assert.Equal(t, "aws_sso", built.Metadata.OAuth.Flow)
}

func TestBuildCredential_RejectsEmptyAllowlist(t *testing.T) {
	t.Parallel()

	_, err := buildFrom(t, validCfg([]string{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accounts")
}

func TestBuildCredential_RejectsDuplicateAccount(t *testing.T) {
	t.Parallel()

	_, err := buildFrom(t, validCfg([]string{"111111111111", "111111111111"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestBuildCredential_RejectsNon12DigitAccount(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"12345", "1234567890123", "12345678901a"} {
		_, err := buildFrom(t, validCfg([]string{bad}))
		require.Error(t, err, "account %q must be rejected", bad)
	}
}
