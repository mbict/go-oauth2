package flow

import (
	"context"
	"github.com/mbict/go-oauth2"
	"net/http"
	"time"
)

type ClientCredentialsRequest struct {
	clientId     oauth2.ClientId
	clientSecret string
	scope        oauth2.Scope
}

func (_ *ClientCredentialsRequest) DecodeRequest(ctx context.Context, req *http.Request) (oauth2.Request, error) {
	if req.FormValue("grant_type") != "client_credentials" {
		return nil, nil
	}

	clientId, clientSecret := resolveClientCredentials(req)
	scope := oauth2.ScopeFromString(req.FormValue("scope"))
	return &ClientCredentialsRequest{
		clientId:     oauth2.ClientId(clientId),
		clientSecret: clientSecret,
		scope:        scope,
	}, nil
}

type ClientCredentialsFlow struct {
	clients      oauth2.ClientStorage
	accessTokens oauth2.AccessTokenStorage
}

func (f *ClientCredentialsFlow) Handle(ctx context.Context, req *ClientCredentialsRequest) (oauth2.Response, error) {

	//authenticate client credentials
	client, err := f.clients.AuthenticateClient(req.clientId, req.clientSecret)
	if err != nil {
		return nil, oauth2.ErrUnauthorizedClient
	}

	//check if all the scopes are there
	if !client.Scope().Has(req.scope) {
		return nil, oauth2.ErrInvalidScope
	}

	//create new access token
	token := ""
	expiresIn := time.Hour * 24

	resp := &AccessTokenResponse{
		AccessToken: token,
		TokenType:   "resource_owner",
		ExpiresIn:   expiresIn,
	}

	return resp, nil
}

func NewClientCredentialsHandler(clients oauth2.ClientStorage, accessTokens oauth2.AccessTokenStorage) *ClientCredentialsFlow {
	return &ClientCredentialsFlow{
		clients:      clients,
		accessTokens: accessTokens,
	}
}
