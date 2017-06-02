package hmac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateFailsWithShortCredentials(t *testing.T) {
	cg := HMACsha{GlobalSecret: []byte("foo")}
	signature, challenge, err := cg.Generate()
	require.NotNil(t, err, "%s", err)
	require.Empty(t, challenge)
	require.Empty(t, signature)
}

func TestGenerate(t *testing.T) {
	cg := HMACsha{
		GlobalSecret: []byte("12345678901234567890"),
	}

	signature, token, err := cg.Generate()
	require.Nil(t, err, "%s", err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, signature)
	t.Logf("Token: %s\n Signature: %s", token, signature)

	err = cg.Validate(token)
	require.Nil(t, err, "%s", err)

	validateSignature, err := cg.Signature(token)
	assert.Nil(t, err)
	assert.Equal(t, signature, validateSignature)

	cg.GlobalSecret = []byte("baz")
	err = cg.Validate(token)
	require.NotNil(t, err, "%s", err)
}

func TestValidateSignatureRejects(t *testing.T) {
	var err error
	cg := HMACsha{
		GlobalSecret: []byte("12345678901234567890"),
	}
	for k, c := range []string{
		"",
		" ",
		"foo.bar",
		"foo.",
		".foo",
	} {
		err = cg.Validate(c)
		assert.NotNil(t, err, "%s", err)
		t.Logf("Passed test case %d", k)
	}
}
