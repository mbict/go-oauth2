package handler

import (
	"context"
	"github.com/mbict/go-oauth2"
)

type TokenHandler struct {
	accessTokenHandler       *oauth2.AccessTokenHandler
	resourceOwnerHandler     *oauth2.ResourceOwnerHandler
	clientCredentialsHandler *oauth2.ClientCredentialsHandler
	refreshHandler           *oauth2.RefreshHandler
}

func NewTokenHandler(tokenStorage oauth2.TokenStorage, userStorage oauth2.UserStorage, authCodeStrategy oauth2.TokenStrategy, accessTokenStrategy oauth2.TokenStrategy, refreshTokenStrategy oauth2.TokenStrategy, scopeRefreshToken string) oauth2.Handler {
	return &TokenHandler{
		accessTokenHandler:       oauth2.NewAccessTokenHandler(tokenStorage, tokenStorage, tokenStorage, authCodeStrategy, accessTokenStrategy, refreshTokenStrategy, scopeRefreshToken),
		resourceOwnerHandler:     oauth2.NewResourceOwnerHandler(userStorage, tokenStorage, accessTokenStrategy),
		clientCredentialsHandler: oauth2.NewClientCredentialsHandler(tokenStorage, accessTokenStrategy),
		refreshHandler:           oauth2.NewRefreshHandler(tokenStorage, tokenStorage),
	}
}

func (h *TokenHandler) Handle(ctx context.Context, req oauth2.Request) (oauth2.Response, error) {
	switch t := req.(type) {
	case oauth2.AccessTokenRequest:
		return h.accessTokenHandler.Handle(ctx, t)
	case *oauth2.ResourceOwnerRequest:
		return h.resourceOwnerHandler.Handle(ctx, t)
	case *oauth2.ClientCredentialsRequest:
		return h.clientCredentialsHandler.Handle(ctx, t)
	case *oauth2.RefreshRequest:
		return h.refreshHandler.Handle(ctx, t)
	}
	return nil, oauth2.ErrInvalidRequest
}
