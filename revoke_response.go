package oauth2

import (
	"context"
	"net/http"
)

type RevokeTokenResponse struct {
}

func (f *RevokeTokenResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	rw.WriteHeader(http.StatusOK)
	return nil
}
