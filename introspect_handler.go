package oauth2

import (
	"context"
)

type IntrospectHandler struct {
	clients       ClientStorage
	accessTokens  AccessTokenStorage
	refreshTokens RefreshTokenStorage
}

func (f *IntrospectHandler) Handle(ctx context.Context, req *IntrospectRequest) (Response, error) {
	//authenticate client credentials
	_, err := f.clients.AuthenticateClient(req.clientId, req.clientSecret)
	if err != nil {
		return nil, ErrUnauthorizedClient
	}

	var token Token
	if req.tokenType == "" || req.tokenType == "access_token" {
		token, err = f.accessTokens.GetAccessTokenSession(req.token)
		if err != nil {
			return nil, ErrInvalidRequest
		}
	}

	if req.tokenType == "" || req.tokenType == "refresh_token" {
		token, err = f.refreshTokens.GetRefreshTokenSession(req.token)
		if err != nil {
			return nil, ErrInvalidRequest
		}
	}

	if token == nil {
		return &IntrospectResponse{
			Active: false,
		}, nil
	}

	//if we got a user session we provide the username
	username := ""
	if token.Session() != nil {
		username = token.Session().Username()
	}

	return &IntrospectResponse{
		Active:    true,
		Scope:     token.Scope(),
		TokenType: token.Type(),
		Username:  username,
		ClientId:  token.ClientId(),
	}, nil
}

func NewIntrospectHandler(clients ClientStorage, accessTokens AccessTokenStorage, refreshTokens RefreshTokenStorage) *IntrospectHandler {
	return &IntrospectHandler{
		clients:       clients,
		accessTokens:  accessTokens,
		refreshTokens: refreshTokens,
	}

}
