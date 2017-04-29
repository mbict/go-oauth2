package flow

import (
	"context"
	"net/http"
	"net/url"
)

type AuthenticateResponse struct {
	RedirectUri *url.URL
}

func (r *AuthenticateResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	rw.Header().Set("Location", r.RedirectUri.String())
	rw.WriteHeader(http.StatusFound)
	return nil
}
