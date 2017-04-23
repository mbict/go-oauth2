package flow

import (
	"context"
	"github.com/mbict/go-oauth2"
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
	Scope     oauth2.Scope
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

type ImplicitAuthorizeFlow struct {
	clients      oauth2.ClientStorage
	accessTokens oauth2.AccessTokenStorage
}

func (f *ImplicitAuthorizeFlow) Handle(ctx context.Context, req *AuthorizeRequest) (oauth2.Response, error) {
	if !req.ResponseTypes.Contains(oauth2.TOKEN) {
		return nil, oauth2.ErrInvalidRequest
	}

	//find  client
	client, err := f.clients.GetClient(req.ClientId)
	if err != nil {
		return nil, oauth2.ErrUnauthorizedClient
	}

	// validate redirect uri is registered
	if !hasRedirectUri(client.RedirectUri(), req.RedirectUri.String()) {
		return nil, oauth2.ErrInvalidRequest
	}

	//check if all the scopes are there
	if !client.Scope().Has(req.Scope) {
		return nil, oauth2.ErrInvalidScope
	}

	//ok we create a new access token
	accessToken := ""
	expiresIn := time.Hour * 24

	resp := &ImplicitAuthorizeResponse{
		AccessToken: accessToken,
		TokenType:   "implicit_authorization",
		ExpiresIn:   expiresIn,
		Scope:       req.Scope,
		State:       req.State,
	}

	return resp, nil
}

func NewImplicitAuthorizeHandler(clients oauth2.ClientStorage, accessTokens oauth2.AccessTokenStorage) *ImplicitAuthorizeFlow {
	return &ImplicitAuthorizeFlow{
		clients:      clients,
		accessTokens: accessTokens,
	}
}
