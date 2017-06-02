package oauth2

import (
	"context"
)

type AuthorizeCodeHandler struct {
	codeStorage           AuthorizeCodeStorage
	authorizeCodeStrategy AuthorizeCodeStrategy
	scopeStrategy         ScopeStrategy
}

func (h *AuthorizeCodeHandler) Handle(ctx context.Context, req AuthorizeRequest, resp AuthorizeResponse) (bool, error) {
	//will only be triggered when response type is code
	if !req.ResponseTypes().Contains(CODE) {
		return false, nil
	}

	if !req.Client().ResponseTypes().Contains(CODE) {
		return false, ErrUnsupportedResponseType
	}

	// validate redirect uri is registered for this client
	if req.RedirectUri() != nil && !hasRedirectUri(req.Client().RedirectUri(), req.RedirectUri().String()) {
		return false, ErrInvalidRedirectUri
	}

	//check if all the granted scopes belong to the client
	if !h.scopeStrategy(req.Client().Scope(), req.GrantedScopes()...) {
		return false, ErrInvalidScope
	}

	//generate authorization code
	signature, token, err := h.authorizeCodeStrategy.GenerateAuthorizeCode(ctx, req)
	if err != nil {
		return false, err
	}

	//store signature
	if err := h.codeStorage.CreateAuthorizeCodeSession(ctx, signature, req); err != nil {
		return false, err
	}

	resp.AddQuery("code", token)
	if len(req.State()) > 0 {
		resp.AddQuery("state", req.State())
	}

	return true, nil
}

func NewAuthorizeCodeHandler(storage AuthorizeCodeStorage, authorizeCodeStrategy AuthorizeCodeStrategy, scopeStrategy ScopeStrategy) *AuthorizeCodeHandler {
	return &AuthorizeCodeHandler{
		codeStorage:           storage,
		authorizeCodeStrategy: authorizeCodeStrategy,
		scopeStrategy:         scopeStrategy,
	}
}
