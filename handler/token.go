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

func NewTokenHandler() oauth2.Handler {
	return &TokenHandler{
		accessTokenHandler:       flow.NewAccessTokenHandler(),
		resourceOwnerHandler:     flow.NewResourceOwnerHandler(),
		clientCredentialsHandler: flow.NewClientCredentialsHandler(),
		refreshHandler:           flow.NewRefreshHandler(),
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
