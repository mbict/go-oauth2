package handler

import (
	"context"
	"github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/flow"
)

type AuthorizeHandler struct {
	authorizeCodeHandler     *flow.AuthorizeCodeFlow
	implicitAuthorizeHandler *flow.ImplicitAuthorizeFlow
}

func NewAuthorizeHandler(clients oauth2.ClientStorage, tokens oauth2.TokenStorage) oauth2.Handler {
	return &AuthorizeHandler{
		authorizeCodeHandler:     flow.NewAuthorizeCodeHandler(clients, tokens),
		implicitAuthorizeHandler: flow.NewImplicitAuthorizeHandler(clients, tokens),
	}
}

func (h *AuthorizeHandler) Handle(ctx context.Context, req oauth2.Request) (oauth2.Response, error) {
	switch t := req.(type) {
	case *flow.AuthorizeCodeRequest:
		return h.authorizeCodeHandler.Handle(ctx, t)
	case *flow.ImplicitAuthorizeRequest:
		return h.implicitAuthorizeHandler.Handle(ctx, t)
	}
	return nil, oauth2.ErrInvalidRequest
}
