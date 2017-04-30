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

func NewTokenHandler(clients oauth2.ClientStorage, users oauth2.UserStorage, sessions oauth2.SessionStorage, tokens oauth2.TokenStorage) oauth2.Handler {
	return &TokenHandler{
		accessTokenHandler:       oauth2.NewAccessTokenHandler(clients, tokens, tokens, tokens),
		resourceOwnerHandler:     oauth2.NewResourceOwnerHandler(clients, users, sessions, tokens),
		clientCredentialsHandler: oauth2.NewClientCredentialsHandler(clients, tokens),
		refreshHandler:           oauth2.NewRefreshHandler(clients, tokens, tokens),
	}
}

func (h *TokenHandler) Handle(ctx context.Context, req oauth2.Request) (oauth2.Response, error) {
	switch t := req.(type) {
	case *oauth2.AccessTokenRequest:
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
