package oauth2

import (
	"context"
	"time"
)

type ResourceOwnerHandler struct {
	clients      ClientStorage
	users        UserStorage
	sessions     SessionStorage
	accessTokens AccessTokenStorage
}

func (f *ResourceOwnerHandler) Handle(ctx context.Context, req *ResourceOwnerRequest) (Response, error) {
	//authenticate client credentials
	client, err := f.clients.AuthenticateClient(req.clientId, req.clientSecret)
	if err != nil {
		return nil, ErrUnauthorizedClient
	}

	username, err := f.users.AuthenticateUser(req.username, req.password)
	if err != nil {
		return nil, ErrUnauthorizedClient
	}

	//check if all the scopes are there
	if !client.Scope().Has(req.scope) {
		return nil, ErrInvalidScope
	}

	//create a session for the authenticated user
	f.sessions.NewSession(client.ClientId(), username)

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

func NewResourceOwnerHandler(clients ClientStorage, users UserStorage, sessions SessionStorage, accessTokens AccessTokenStorage) *ResourceOwnerHandler {
	return &ResourceOwnerHandler{
		clients:      clients,
		users:        users,
		sessions:     sessions,
		accessTokens: accessTokens,
	}
}
