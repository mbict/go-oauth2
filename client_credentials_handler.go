package oauth2

import (
	"context"
	"time"
)

type ClientCredentialsHandler struct {
	accessTokenStorage  AccessTokenStorage
	accessTokenStrategy AccessTokenStrategy
}

func (h *ClientCredentialsHandler) Handle(ctx context.Context, req *ClientCredentialsRequest) (Response, error) {

	//check if all the scopes are there
	//if !client.Scope().Has(req.scope) {
	//	return nil, ErrInvalidScope
	//}

	//create new access token
	signature, token, err := h.accessTokenStrategy.GenerateAccessToken(ctx, req.Session())
	if err != nil {
		return nil, err
	}

	//store signature
	if err := h.accessTokenStorage.CreateAccessTokenSession(ctx, signature, req); err != nil {
		return nil, err
	}
	expiresIn := time.Until(req.Session().ExpiresAt())

	resp := &accessTokenResponse{
		accessToken: token,
		tokenType:   "Bearer",
		expiresIn:   expiresIn,
		data:        make(map[string]interface{}),
	}

	return resp, nil
}

func NewClientCredentialsHandler(accessTokenStorage AccessTokenStorage, accessTokenStrategy AccessTokenStrategy) *ClientCredentialsHandler {
	return &ClientCredentialsHandler{
		accessTokenStorage:  accessTokenStorage,
		accessTokenStrategy: accessTokenStrategy,
	}
}
