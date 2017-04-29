package handler

import (
	"context"
	"github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/flow"
)

type AuthorizeHandler struct {
	authorizeCodeHandler     *flow.AuthorizeCodeFlow
	implicitAuthorizeHandler *flow.ImplicitAuthorizeFlow
	authenticateStrategy     flow.AuthenticateStrategyFunc
}

func NewAuthorizeHandler(clients oauth2.ClientStorage, tokens oauth2.TokenStorage, authenticateStrategy flow.AuthenticateStrategyFunc) oauth2.Handler {
	return &AuthorizeHandler{
		authorizeCodeHandler:     flow.NewAuthorizeCodeHandler(clients, tokens),
		implicitAuthorizeHandler: flow.NewImplicitAuthorizeHandler(clients, tokens),
		authenticateStrategy:     authenticateStrategy,
	}
}

func (h *AuthorizeHandler) Handle(ctx context.Context, req oauth2.Request) (oauth2.Response, error) {
	if ar, ok := req.(*flow.AuthorizeRequest); ok {
		if ar.Session == nil {
			resp, err := h.authenticateStrategy(ctx, ar)
			if err != nil {
				return nil, oauth2.ErrAuthenticateFailed
			}

			if resp != nil {
				return resp, nil
			}
		}

		if ar.Session == nil {
			return nil, oauth2.ErrAuthenticateFailed
		}

		if ar.ResponseTypes.Contains(oauth2.CODE) {
			return h.authorizeCodeHandler.Handle(ctx, ar)
		}

		if ar.ResponseTypes.Contains(oauth2.TOKEN) {
			return h.implicitAuthorizeHandler.Handle(ctx, ar)
		}
	}
	return nil, oauth2.ErrInvalidRequest
}
