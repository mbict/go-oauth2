package oauth2

import (
	"context"
	"time"
)

type ResourceOwnerHandler struct {
	userStorage         UserStorage
	accessTokenStorage  AccessTokenStorage
	accessTokenStrategy TokenStrategy
}

func (h *ResourceOwnerHandler) Handle(ctx context.Context, req *ResourceOwnerRequest) (Response, error) {

	//check if all the scopes are there
	if !req.Client().Scope().Has(req.Session().GrantedScopes()) {
		return nil, ErrInvalidScope
	}

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
		tokenType:   "resource_owner",
		expiresIn:   expiresIn,
		data:        make(map[string]interface{}),
	}

	return resp, nil
}

func NewResourceOwnerHandler(userStorage UserStorage, accessTokenStorage AccessTokenStorage, accessTokenStrategy TokenStrategy) *ResourceOwnerHandler {
	return &ResourceOwnerHandler{
		userStorage:         userStorage,
		accessTokenStorage:  accessTokenStorage,
		accessTokenStrategy: accessTokenStrategy,
	}
}
