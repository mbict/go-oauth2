package oauth2

import (
	"context"
)

type AuthorizeCodeHandler struct {
	clients              ClientStorage
	codes                AuthorizeCodeStorage
	authenticateStrategy AuthenticateStrategyFunc
}

func (f *AuthorizeCodeHandler) Handle(ctx context.Context, req *AuthorizeRequest) (Response, error) {
	if !req.ResponseTypes.Contains(CODE) {
		return nil, ErrInvalidRequest
	}

	//find client
	client, err := f.clients.GetClient(req.ClientId)
	if err != nil {
		return nil, ErrUnauthorizedClient
	}

	// validate redirect uri is registered
	if !hasRedirectUri(client.RedirectUri(), req.RedirectUri.String()) {
		return nil, ErrInvalidRequest
	}

	//check if all the scopes are there
	if len(req.Scope) > 0 && !client.Scope().Has(req.Scope) {
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

	//generate authorization code
	code := "testcode"

	resp := &AuthorizeCodeResponse{
		Code:        code,
		State:       req.State,
		RedirectUri: req.RedirectUri,
	}

	return resp, nil
}

func NewAuthorizeCodeHandler(clients ClientStorage, codes AuthorizeCodeStorage, authenticateStrategy AuthenticateStrategyFunc) *AuthorizeCodeHandler {
	return &AuthorizeCodeHandler{
		clients:              clients,
		codes:                codes,
		authenticateStrategy: authenticateStrategy,
	}
}
