package handler

import (
	"context"
	"github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/flow"
)

type TokenHandler struct {
	accessTokenHandler       *flow.AccessTokenFlow
	resourceOwnerHandler     *flow.ResourceOwnerFlow
	clientCredentialsHandler *flow.ClientCredentialsFlow
	refreshHandler           *flow.RefreshFlow
}

func NewTokenHandler(clients oauth2.ClientStorage, users oauth2.UserStorage, sessions oauth2.SessionStorage, tokens oauth2.TokenStorage) oauth2.Handler {
	return &TokenHandler{
		accessTokenHandler:       flow.NewAccessTokenHandler(clients, tokens, tokens, tokens),
		resourceOwnerHandler:     flow.NewResourceOwnerHandler(clients, users, sessions, tokens),
		clientCredentialsHandler: flow.NewClientCredentialsHandler(clients, tokens),
		refreshHandler:           flow.NewRefreshHandler(clients, tokens, tokens),
	}
}

func (h *TokenHandler) Handle(ctx context.Context, req oauth2.Request) (oauth2.Response, error) {
	switch t := req.(type) {
	case *flow.AccessTokenRequest:
		return h.accessTokenHandler.Handle(ctx, t)
	case *flow.ResourceOwnerRequest:
		return h.resourceOwnerHandler.Handle(ctx, t)
	case *flow.ClientCredentialsRequest:
		return h.clientCredentialsHandler.Handle(ctx, t)
	case *flow.RefreshRequest:
		return h.refreshHandler.Handle(ctx, t)
	}
	return nil, oauth2.ErrInvalidRequest
}
