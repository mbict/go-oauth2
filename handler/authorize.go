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

func NewAuthorizeHandler() oauth2.Handler {
	return &AuthorizeHandler{
		authorizeCodeHandler:     flow.NewAuthorizeCodeHandler(),
		implicitAuthorizeHandler: flow.NewImplicitAuthorizeHandler(),
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
