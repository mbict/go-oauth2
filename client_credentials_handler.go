package oauth2

import (
	"context"
	"time"
)

type ClientCredentialsHandler struct {
	clients      ClientStorage
	accessTokens AccessTokenStorage
}

func (f *ClientCredentialsHandler) Handle(ctx context.Context, req *ClientCredentialsRequest) (Response, error) {

	//authenticate client credentials
	client, err := f.clients.AuthenticateClient(req.clientId, req.clientSecret)
	if err != nil {
		return nil, ErrUnauthorizedClient
	}

	//check if all the scopes are there
	if !client.Scope().Has(req.scope) {
		return nil, ErrInvalidScope
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

func NewClientCredentialsHandler(clients ClientStorage, accessTokens AccessTokenStorage) *ClientCredentialsHandler {
	return &ClientCredentialsHandler{
		clients:      clients,
		accessTokens: accessTokens,
	}
}
