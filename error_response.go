package oauth2

import (
	"context"
	"net/http"
	"net/url"
)

type ErrorResponse struct {
	RedirectUri *url.URL
	Error       error
	Description string
	Uri         *url.URL
	State       string
	Query       map[string]string
}

func (r *ErrorResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	q := r.RedirectUri.Query()
	if r.Error != nil {
		q.Add("error", r.Error.Error())
	}
	if r.Description != "" {
		q.Add("error_description", r.Description)
	}
	if r.Uri != nil {
		q.Add("error_uri", r.Uri.String())
	}
	if r.State != "" {
		q.Add("state", r.State)
	}

	for k, v := range r.Query {
		q.Add(k, v)
	}

	r.RedirectUri.RawQuery = q.Encode()

	rw.Header().Set("Location", r.RedirectUri.String())
	rw.WriteHeader(http.StatusFound)
	return nil
}
