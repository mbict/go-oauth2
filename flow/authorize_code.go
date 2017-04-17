package flow

import (
	"auth/session"
	"context"
	"github.com/mbict/go-oauth2"
	"net/http"
	"net/url"
)

type AuthorizeCodeRequest struct {
	clientId    oauth2.ClientId
	redirectUri *url.URL
	scope       oauth2.Scope
	state       string
	session     *session.Session
}

func (_ *AuthorizeCodeRequest) Type() string {
	return "AuthorizeCode"
}

func (_ *AuthorizeCodeRequest) DecodeRequest(ctx context.Context, req *http.Request) (oauth2.Request, error) {
	if req.FormValue("response_type") != "code" {
		return nil, nil
	}

	//redirect url parsing and encoding
	rawRedirectUri := req.FormValue("redirect_uri")
	redirectUri, err := url.Parse(rawRedirectUri)
	if err != nil {
		return nil, oauth2.ErrInvalidRequest
	}

	clientId := req.FormValue("client_id")
	scope := oauth2.ScopeFromString(req.FormValue("scope"))
	state := req.FormValue("state")

	return &AuthorizeCodeRequest{
		clientId:    oauth2.ClientId(clientId),
		redirectUri: redirectUri,
		scope:       scope,
		state:       state,
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

	rw.Header().Set("Location", r.RedirectUri.RequestURI())
	rw.WriteHeader(http.StatusFound)
	return nil
}

type AuthorizeCodeFlow struct {
	clients oauth2.ClientStorage
	codes   oauth2.AuthorizeCodeStorage
}

func (f *AuthorizeCodeFlow) Handle(ctx context.Context, req *AuthorizeCodeRequest) (oauth2.Response, error) {
	//find client
	client, err := f.clients.GetClient(req.clientId)
	if err != nil {
		return nil, oauth2.ErrUnauthorizedClient
	}

	// validate redirect uri is registered
	if !client.HasRedirectUri(req.redirectUri.String()) {
		return nil, oauth2.ErrInvalidRequest
	}

	//check if all the scopes are there
	if !client.Scope.Has(req.scope) {
		return nil, oauth2.ErrInvalidScope
	}

	//generate authorization code
	code := ""

	resp := &AuthorizeCodeResponse{
		Code:        code,
		State:       req.state,
		RedirectUri: req.redirectUri,
	}

	return resp, nil
}

func NewAuthorizeCodeHandler() *AuthorizeCodeFlow {
	return &AuthorizeCodeFlow{}
}
