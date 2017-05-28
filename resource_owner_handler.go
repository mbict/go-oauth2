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
	if !req.Client().Scope().Has(req.GrantedScopes()) {
		return nil, ErrInvalidScope
	}

	//create new access token
	signature, token, err := h.accessTokenStrategy.Generate(req)
	if err != nil {
		return nil, err
	}

	//store signature
	if err := h.accessTokenStorage.CreateAccessTokenSession(ctx, signature, req); err != nil {
		return nil, err
	}
	expiresIn := time.Until(req.Session().ExpiresAt())

	resp := &AccessTokenResponse{
		AccessToken: token,
		TokenType:   "resource_owner",
		ExpiresIn:   expiresIn,
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
