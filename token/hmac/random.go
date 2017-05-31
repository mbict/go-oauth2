package hmac

import (
	"crypto/rand"
	"github.com/pkg/errors"
	"io"
)

// randomBytes returns n random bytes by reading from crypto/rand.Reader
func randomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return []byte{}, errors.WithStack(err)
	}
	return bytes, nil
}
