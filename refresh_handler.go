package oauth2

import (
	"context"
	"time"
)

type RefreshHandler struct {
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

	resp := &accessTokenResponse{
		accessToken:  accessToken,
		tokenType:    "resource_owner",
		expiresIn:    expiresIn,
		refreshToken: refreshToken,
		data:         make(map[string]interface{}),
	}

	return resp, nil
}

func NewRefreshHandler(refreshTokens RefreshTokenStorage, accessTokens AccessTokenStorage) *RefreshHandler {
	return &RefreshHandler{
		refreshTokens: refreshTokens,
		accessTokens:  accessTokens,
	}
}
