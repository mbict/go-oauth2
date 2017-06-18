package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
)

type AuthorizeErrorResponse interface {
	Response
	OAuthError
}

type authorizeErrorResponse struct {
	request AuthorizeRequest
	OAuthError
}

func (r *authorizeErrorResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	rfcErr := r.RFC6749()
	if r.OAuthError == ErrInvalidRedirectUri || r.OAuthError == ErrUnauthorizedClient {
		data, err := json.MarshalIndent(rfcErr, "", "\t")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return nil
		}

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(rfcErr.Code)
		_, err = rw.Write(data)
		return err
	}

	redirectURI := r.request.RedirectUri()
	q := redirectURI.Query()

	q.Add("error", rfcErr.Name)
	if rfcErr.Description != "" {
		q.Add("error_description", rfcErr.Description)
	}

	if r.request.State() != "" {
		q.Add("state", r.request.State())
	}

	redirectURI.RawQuery = q.Encode()
	rw.Header().Add("Location", redirectURI.String())
	rw.WriteHeader(http.StatusFound)
	return nil
}

func NewAuthorizeErrorResponse(err OAuthError, req AuthorizeRequest) AuthorizeErrorResponse {
	return &authorizeErrorResponse{
		request:    req,
		OAuthError: err,
	}
}
