package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type ImplicitAuthorizeResponse struct {
	RedirectUri url.URL
	AccessToken string
	TokenType   string
	// ExpiresIn in seconds
	ExpiresIn time.Duration
	Scope     Scope
	State     string
}

func (r *ImplicitAuthorizeResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	q := r.RedirectUri.Query()
	q.Add("access_token", r.AccessToken)
	q.Add("token_type", r.TokenType)

	if r.ExpiresIn.Seconds() > 0 {
		q.Add("expires_in", strconv.Itoa(int(r.ExpiresIn.Seconds())))
	}

	if len(r.Scope) > 0 {
		q.Add("scope", r.Scope.String())
	}

	if r.State != "" {
		q.Add("state", r.State)
	}
	r.RedirectUri.RawQuery = q.Encode()

	rw.Header().Set("Location", r.RedirectUri.String())
	rw.WriteHeader(http.StatusFound)
	return nil
}
