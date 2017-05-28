package oauth2

import (
	"context"
	"time"
)

type RefreshHandler struct {
	clients       ClientStorage
	refreshTokens RefreshTokenStorage
	accessTokens  AccessTokenStorage
}

func (f *RefreshHandler) Handle(ctx context.Context, req *RefreshRequest) (Response, error) {

	////get the refresh token from storage
	//token, err := h.refreshTokens.GetRefreshTokenSession(req.refreshToken)
	//if err != nil || token.ClientId() != client.ClientId() {
	//	return nil, ErrInvalidRequest
	//}
	//
	////check if all the scopes are valid
	//if !token.Scope().Has(req.scope) {
	//	return nil, ErrInvalidScope
	//}

	//issue a new access token
	accessToken := ""
	expiresIn := time.Hour * 24

	//create a new refresh token if the scope differs from the stored refresh scope
	refreshToken := ""

	resp := &AccessTokenResponse{
		AccessToken:  accessToken,
		TokenType:    "resource_owner",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
	}

	return resp, nil
}

func NewRefreshHandler(clients ClientStorage, refreshTokens RefreshTokenStorage, accessTokens AccessTokenStorage) *RefreshHandler {
	return &RefreshHandler{
		clients:       clients,
		refreshTokens: refreshTokens,
		accessTokens:  accessTokens,
	}
}
