package flow

import (
	"context"
	"github.com/mbict/go-oauth2"
	"net/http"
	"net/url"
)

type AuthorizeRequest struct {
	ResponseTypes oauth2.ResponseTypes
	ClientId      oauth2.ClientId
	RedirectUri   *url.URL
	Scope         oauth2.Scope
	State         string
	Session       *oauth2.Session
}

func (_ *AuthorizeRequest) DecodeRequest(ctx context.Context, req *http.Request) (oauth2.Request, error) {
	responseTypes := oauth2.ResponseTypeFromString(req.FormValue("response_type"))

	//redirect url parsing and encoding
	rawRedirectUri := req.FormValue("redirect_uri")
	redirectUri, err := url.Parse(rawRedirectUri)
	if err != nil {
		return nil, oauth2.ErrInvalidRequest
	}

	clientId := req.FormValue("client_id")
	scope := oauth2.ScopeFromString(req.FormValue("scope"))
	state := req.FormValue("state")

	return &AuthorizeRequest{
		ResponseTypes: responseTypes,
		ClientId:      oauth2.ClientId(clientId),
		RedirectUri:   redirectUri,
		Scope:         scope,
		State:         state,
	}, nil
}

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
