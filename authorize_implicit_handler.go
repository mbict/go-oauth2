package oauth2

import (
	"context"
	"time"
)

type ImplicitAuthorizeHandler struct {
	clients              ClientStorage
	accessTokens         AccessTokenStorage
	authenticateStrategy AuthenticateStrategyFunc
}

func (f *ImplicitAuthorizeHandler) Handle(ctx context.Context, req *AuthorizeRequest) (Response, error) {
	if !req.ResponseTypes.Contains(TOKEN) {
		return nil, ErrInvalidRequest
	}

	//find  client
	client, err := f.clients.GetClient(req.ClientId)
	if err != nil {
		return nil, ErrUnauthorizedClient
	}

	// validate redirect uri is registered
	if !hasRedirectUri(client.RedirectUri(), req.RedirectUri.String()) {
		return nil, ErrInvalidRequest
	}

	//check if all the scopes are there
	if !client.Scope().Has(req.Scope) {
		return nil, ErrInvalidScope
	}

	//we need an authenticated session
	if req.HasSession() == false {
		resp, err := f.authenticateStrategy(ctx, req)
		if err != nil || resp != nil {
			return resp, err
		}
	}

	if req.HasSession() == false {
		return nil, ErrAuthenticateFailed
	}

	//ok we create a new access token
	accessToken := ""
	expiresIn := time.Hour * 24

	resp := &ImplicitAuthorizeResponse{
		AccessToken: accessToken,
		TokenType:   "implicit_authorization",
		ExpiresIn:   expiresIn,
		Scope:       req.Scope,
		State:       req.State,
	}

	return resp, nil
}

func NewImplicitAuthorizeHandler(clients ClientStorage, accessTokens AccessTokenStorage, authenticateStrategy AuthenticateStrategyFunc) *ImplicitAuthorizeHandler {
	return &ImplicitAuthorizeHandler{
		clients:              clients,
		accessTokens:         accessTokens,
		authenticateStrategy: authenticateStrategy,
	}
}
