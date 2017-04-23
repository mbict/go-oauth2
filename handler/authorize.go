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
	if ar, ok := req.(*flow.AuthorizeRequest); ok {
		if ar.ResponseTypes.Contains(oauth2.CODE) {
			return h.authorizeCodeHandler.Handle(ctx, ar)
		}

		if ar.ResponseTypes.Contains(oauth2.TOKEN) {
			return h.implicitAuthorizeHandler.Handle(ctx, ar)
		}
	}
	return nil, oauth2.ErrInvalidRequest
}
