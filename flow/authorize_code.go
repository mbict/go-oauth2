package flow

import (
	"context"
	"github.com/mbict/go-oauth2"
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

type AuthorizeCodeFlow struct {
	clients oauth2.ClientStorage
	codes   oauth2.AuthorizeCodeStorage
}

func (f *AuthorizeCodeFlow) Handle(ctx context.Context, req *AuthorizeRequest) (oauth2.Response, error) {
	if !req.ResponseTypes.Contains(oauth2.CODE) {
		return nil, oauth2.ErrInvalidRequest
	}

	//find client
	client, err := f.clients.GetClient(req.ClientId)
	if err != nil {
		return nil, oauth2.ErrUnauthorizedClient
	}

	// validate redirect uri is registered
	if !hasRedirectUri(client.RedirectUri(), req.RedirectUri.String()) {
		return nil, oauth2.ErrInvalidRequest
	}

	//check if all the scopes are there
	if len(req.Scope) > 0 && !client.Scope().Has(req.Scope) {
		return nil, oauth2.ErrInvalidScope
	}

	//generate authorization code
	code := "testcode"

	resp := &AuthorizeCodeResponse{
		Code:        code,
		State:       req.State,
		RedirectUri: req.RedirectUri,
	}

	return resp, nil
}

func NewAuthorizeCodeHandler(clients oauth2.ClientStorage, codes oauth2.AuthorizeCodeStorage) *AuthorizeCodeFlow {
	return &AuthorizeCodeFlow{
		clients: clients,
		codes:   codes,
	}
}
