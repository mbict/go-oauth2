package handler

import (
	"context"
	"github.com/mbict/go-oauth2"
)

type AuthHandler struct {
	handlers []oauth2.AuthorizeHandler
	//authorizeCodeHandler     *oauth2.AuthorizeCodeHandler
	//implicitAuthorizeHandler *oauth2.ImplicitAuthorizeHandler
}

func NewAuthorizeHandler(authorizeCodeStorage oauth2.AuthorizeCodeStorage, accessTokenStorage oauth2.AccessTokenStorage, authorizeCodeStrategy oauth2.TokenStrategy, accessTokenStrategy oauth2.TokenStrategy, scopeStrategy oauth2.ScopeStrategy) oauth2.Handler {
	return &AuthHandler{
		handlers: []oauth2.AuthorizeHandler{
			oauth2.NewAuthorizeCodeHandler(authorizeCodeStorage, authorizeCodeStrategy, scopeStrategy),
			oauth2.NewImplicitAuthorizeHandler(accessTokenStorage, accessTokenStrategy, scopeStrategy),
		},
	}
}

func (h *AuthHandler) Handle(ctx context.Context, req oauth2.Request) (oauth2.Response, error) {
	if ar, ok := req.(oauth2.AuthorizeRequest); ok {
		resp := oauth2.NewAuthorizeResponse(ar.RedirectUri().String())

		handled := false
		for _, ah := range h.handlers {
			rh, err := ah.Handle(ctx, ar, resp)
			if err != nil {
				return nil, err
			}
			handled = handled || rh
		}

		//not handled
		if handled == false {
			return nil, oauth2.ErrUnsupportedResponseType
		}
		return resp, nil
	}
	return nil, oauth2.ErrInvalidRequest
}
