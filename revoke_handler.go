package oauth2

import (
	"context"
)

type RevokeTokenHandler struct {
	clients        ClientStorage
	authorizeCodes AuthorizeCodeStorage
	accessTokens   AccessTokenStorage
	refreshTokens  RefreshTokenStorage
}

func (f *RevokeTokenHandler) Handle(ctx context.Context, req *RevokeTokenRequest) (Response, error) {
	//authenticate client credentials
	_, err := f.clients.AuthenticateClient(req.clientId, req.clientSecret)
	if err != nil {
		return nil, ErrUnauthorizedClient
	}

	//check if there is no unsupported toke type requested
	if req.tokenType != "" &&
		req.tokenType != "authorize_code" &&
		req.tokenType != "refresh_token" &&
		req.tokenType != "access_token" {
		return nil, ErrUnsupportedTokenType
	}

	//revoke authorize code
	if req.tokenType == "" || req.tokenType == "authorize_code" {
		_, err := f.authorizeCodes.DeleteAuthorizeCodeSession(req.token)
		if err != nil && err != ErrCodeNotFound {
			return nil, err
		}
	}

	//revoke refresh token
	if req.tokenType == "" || req.tokenType == "refresh_token" {
		_, err := f.refreshTokens.DeleteRefreshTokenSession(req.token)
		if err != nil && err != ErrTokenNotFound {
			return nil, err
		}
	}

	//revoke access token
	if req.tokenType == "" || req.tokenType == "access_token" {
		_, err := f.accessTokens.DeleteAccessTokenSession(req.token)
		if err != nil && err != ErrTokenNotFound {
			return nil, err
		}
	}

	return &RevokeTokenResponse{}, nil
}

func NewRevokeTokenHandler(clients ClientStorage, authorizeCodes AuthorizeCodeStorage, accessTokens AccessTokenStorage, refreshTokens RefreshTokenStorage) *RevokeTokenHandler {
	return &RevokeTokenHandler{
		clients:        clients,
		authorizeCodes: authorizeCodes,
		accessTokens:   accessTokens,
		refreshTokens:  refreshTokens,
	}
}
