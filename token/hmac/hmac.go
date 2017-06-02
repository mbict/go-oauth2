package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/mbict/go-oauth2"
	"github.com/pkg/errors"
)

const (
	// key should be at least 256 bit long, making it
	minimumEntropy = 32

	// the secrets (client and global) should each have at least 16 characters making it harder to guess them
	minimumSecretLength = 32
)

var b64 = base64.URLEncoding.WithPadding(base64.NoPadding)

type HMACsha struct {
	AuthCodeEntropy int
	GlobalSecret    []byte
}

func (s *HMACsha) Signature(token string) (string, error) {
	split := strings.Split(token, ".")

	if err := s.Validate(token); err != nil {
		return "", err
	}
	if len(split) != 2 {
		return "", oauth2.ErrInvalidToken
	}

	return split[1], nil
}

// Validate validates a token and returns its signature or an error if the token is not valid.
func (s *HMACsha) Validate(token string) error {
	split := strings.Split(token, ".")
	if len(split) != 2 {
		return errors.WithStack(oauth2.ErrInvalidToken)
	}

	key := split[0]
	signature := split[1]
	if key == "" || signature == "" {
		return errors.WithStack(oauth2.ErrInvalidToken)
	}

	decodedSignature, err := b64.DecodeString(signature)
	if err != nil {
		return errors.WithStack(err)
	}

	decodedKey, err := b64.DecodeString(key)
	if err != nil {
		return errors.WithStack(err)
	}

	useSecret := append([]byte{}, s.GlobalSecret...)
	mac := hmac.New(sha256.New, useSecret)
	_, err = mac.Write(decodedKey)
	if err != nil {
		return errors.WithStack(err)
	}

	if !hmac.Equal(decodedSignature, mac.Sum([]byte{})) {
		// Hash is invalid
		return errors.WithStack(oauth2.ErrInvalidSignature)
	}

	return nil
}

// Generate will return a signature and token
func (s *HMACsha) Generate() (string, string, error) {
	if len(s.GlobalSecret) < minimumSecretLength/2 {
		return "", "", errors.New("Secret is not strong enough")
	}

	if s.AuthCodeEntropy < minimumEntropy {
		s.AuthCodeEntropy = minimumEntropy
	}

	//Generate a pseudo random number sequence
	key, err := randomBytes(s.AuthCodeEntropy)
	if err != nil {
		return "", "", errors.WithStack(err)
	}

	if len(key) < s.AuthCodeEntropy {
		return "", "", errors.New("Could not read enough random data for key generation")
	}

	useSecret := append([]byte{}, s.GlobalSecret...)
	mac := hmac.New(sha256.New, useSecret)
	_, err = mac.Write(key)
	if err != nil {
		return "", "", errors.WithStack(err)
	}

	signature := mac.Sum([]byte{})
	encodedSignature := b64.EncodeToString(signature)
	encodedToken := fmt.Sprintf("%s.%s", b64.EncodeToString(key), encodedSignature)
	return encodedSignature, encodedToken, nil
}
