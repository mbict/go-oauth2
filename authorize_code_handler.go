package oauth2

import (
	"context"
)

type AuthorizeCodeHandler struct {
	codeStorage           AuthorizeCodeStorage
	authorizeCodeStrategy TokenStrategy
	scopeStrategy         ScopeStrategy
}

func (h *AuthorizeCodeHandler) Handle(ctx context.Context, req AuthorizeRequest, resp AuthorizeResponse) error {
	//will only be triggered when response type is code
	if !req.ResponseTypes().Contains(CODE) {
		return ErrInvalidRequest
	}

	if !req.Client().ResponseTypes().Contains(CODE) {
		return ErrUnsupportedResponseType
	}

	// validate redirect uri is registered for this client
	if req.RedirectUri() != nil && !hasRedirectUri(req.Client().RedirectUri(), req.RedirectUri().String()) {
		return ErrInvalidRedirectUri
	}

	//check if all the granted scopes belong to the client
	if !h.scopeStrategy(req.Client().Scope(), req.GrantedScopes()...) {
		return ErrInvalidScope
	}

	//generate authorization code
	signature, token, err := h.authorizeCodeStrategy.Generate(req)
	if err != nil {
		return err
	}

	//store signature
	if err := h.codeStorage.CreateAuthorizeCodeSession(ctx, signature, req); err != nil {
		return err
	}

	resp.AddQuery("code", token)
	if len(req.State()) > 0 {
		resp.AddQuery("state", req.State())
	}

	return nil
}

func NewAuthorizeCodeHandler(storage AuthorizeCodeStorage, authorizeCodeStrategy TokenStrategy, scopeStrategy ScopeStrategy) *AuthorizeCodeHandler {
	return &AuthorizeCodeHandler{
		codeStorage:           storage,
		authorizeCodeStrategy: authorizeCodeStrategy,
		scopeStrategy:         scopeStrategy,
	}
}
