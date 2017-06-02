package oauth2

import (
	"context"
	"strconv"
	"time"
)

type ImplicitAuthorizeHandler struct {
	accessTokenStorage  AccessTokenStorage
	accessTokenStrategy AccessTokenStrategy
	scopeStrategy       ScopeStrategy
}

func (h *ImplicitAuthorizeHandler) Handle(ctx context.Context, req AuthorizeRequest, resp AuthorizeResponse) (bool, error) {
	//will only be triggered when response type is code
	if !req.ResponseTypes().Contains(TOKEN) {
		return false, nil
	}

	if !req.Client().ResponseTypes().Contains(TOKEN) {
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

	//we create a new access token
	signature, token, err := h.accessTokenStrategy.GenerateAccessToken(ctx, req)
	if err != nil {
		return false, err
	}

	//store signature
	if err := h.accessTokenStorage.CreateAccessTokenSession(ctx, signature, req); err != nil {
		return false, err
	}

	expiresIn := strconv.Itoa(int(time.Until(req.Session().ExpiresAt()).Seconds()))
	resp.AddQuery("access_token", token)
	resp.AddQuery("expires_in", expiresIn)
	if len(req.State()) > 0 {
		resp.AddQuery("state", req.State())
	}

	if len(req.GrantedScopes()) > 0 {
		resp.AddQuery("scope", req.GrantedScopes().String())
	}

	return true, nil
}

func NewImplicitAuthorizeHandler(accessTokenStorage AccessTokenStorage, accessTokenStrategy AccessTokenStrategy, scopeStrategy ScopeStrategy) *ImplicitAuthorizeHandler {
	return &ImplicitAuthorizeHandler{
		accessTokenStorage:  accessTokenStorage,
		accessTokenStrategy: accessTokenStrategy,
		scopeStrategy:       scopeStrategy,
	}
}
