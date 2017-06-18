package oauth2

import (
	"context"
	"net/http"
	"net/url"
)

type AuthorizeResponse interface {
	Response

	RedirectUri() *url.URL
	AddQuery(name string, value string)
	GetQuery(name string) string
}

type authorizeResponse struct {
	redirectUrl *url.URL
	query       url.Values
}

func (r *authorizeResponse) RedirectUri() *url.URL {
	return r.redirectUrl
}

func (r *authorizeResponse) AddQuery(name string, value string) {
	r.query.Add(name, value)
}

func (r *authorizeResponse) GetQuery(name string) string {
	return r.query.Get(name)
}

func (r *authorizeResponse) EncodeResponse(ctx context.Context, w http.ResponseWriter) error {
	q := r.redirectUrl.Query()
	for k, vs := range r.query {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	r.redirectUrl.RawQuery = q.Encode()

	w.Header().Set("Location", r.redirectUrl.String())
	w.WriteHeader(http.StatusFound)
	return nil
}

func NewAuthorizeResponse(redirectUrl string) AuthorizeResponse {
	rurl, _ := url.Parse(redirectUrl)
	return &authorizeResponse{
		redirectUrl: rurl,
		query:       url.Values{},
	}
}
