package handler

import (
	"context"
	"github.com/mbict/go-oauth2"
)

type AuthorizeHandler struct {
	authorizeCodeHandler     *oauth2.AuthorizeCodeHandler
	implicitAuthorizeHandler *oauth2.ImplicitAuthorizeHandler
	//authenticateStrategy     oauth2.AuthenticateStrategyFunc
}

func NewAuthorizeHandler(clients oauth2.ClientStorage, tokens oauth2.TokenStorage, authenticateStrategy oauth2.AuthenticateStrategyFunc /*, consentStrategy oauth2.ConsentStrategyFunc*/) oauth2.Handler {
	return &AuthorizeHandler{
	//authorizeCodeHandler:     oauth2.NewAuthorizeCodeHandler(clients, tokens, authenticateStrategy/*, consentStrategy*/),
	//implicitAuthorizeHandler: oauth2.NewImplicitAuthorizeHandler(clients, tokens, authenticateStrategy/*, consentStrategy*/),
	}
}

func (h *AuthorizeHandler) Handle(ctx context.Context, req oauth2.Request) (oauth2.Response, error) {
	if ar, ok := req.(*oauth2.AuthorizeRequest); ok {
		if ar.responseTypes.Contains(oauth2.CODE) {
			return h.authorizeCodeHandler.Handle(ctx, ar)
		}

		if ar.responseTypes.Contains(oauth2.TOKEN) {
			return h.implicitAuthorizeHandler.Handle(ctx, ar)
		}
	}
	return nil, oauth2.ErrInvalidRequest
}
