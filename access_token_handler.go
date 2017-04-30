package oauth2

import (
	"context"
	"time"
)

type AccessTokenHandler struct {
	clients       ClientStorage
	codes         AuthorizeCodeStorage
	accessTokens  AccessTokenStorage
	refreshTokens RefreshTokenStorage
}

func (f *AccessTokenHandler) Handle(ctx context.Context, req *AccessTokenRequest) (Response, error) {
	//authenticate client credentials
	client, err := f.clients.AuthenticateClient(req.clientId, req.clientSecret)
	if err != nil {
		return nil, ErrUnauthorizedClient
	}

	//check if code session exists for this client id
	code, err := f.codes.GetAuthorizeCodeSession(req.code)
	if err != nil || code.ClientId() != client.ClientId() {
		return nil, ErrInvalidRequest
	}

	//check if the redirect uri matches the request
	if code.RedirectUri() != req.redirectUri {
		return nil, ErrInvalidRequest
	}

	//ok we remove the code token

	//ok we create new access token

	//ok we create new refresh token

	//create new access token
	accessToken := ""
	refreshToken := ""
	expiresIn := time.Hour * 24

	resp := &AccessTokenResponse{
		AccessToken:  accessToken,
		TokenType:    "resource_owner",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
	}

	return resp, nil
}

func NewAccessTokenHandler(
	clients ClientStorage,
	codes AuthorizeCodeStorage,
	accessTokens AccessTokenStorage,
	refreshTokens RefreshTokenStorage) *AccessTokenHandler {
	return &AccessTokenHandler{
		clients:       clients,
		codes:         codes,
		accessTokens:  accessTokens,
		refreshTokens: refreshTokens,
	}
}
