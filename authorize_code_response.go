package oauth2

import (
	"context"
	"net/http"
	"net/url"
)

type AuthorizeCodeResponse struct {
	RedirectUri *url.URL
	Code        string
	State       string
}

func (r *AuthorizeCodeResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	q := r.RedirectUri.Query()
	q.Add("code", r.Code)

	if r.State != "" {
		q.Add("state", r.State)
	}
	r.RedirectUri.RawQuery = q.Encode()

	rw.Header().Set("Location", r.RedirectUri.String())
	rw.WriteHeader(http.StatusFound)
	return nil
}
