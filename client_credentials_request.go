package oauth2

import (
	"context"
	"net/http"
)

type ClientCredentialsRequest struct {
	clientId     ClientId
	clientSecret string
	scope        Scope
}

func (_ *ClientCredentialsRequest) DecodeRequest(ctx context.Context, req *http.Request) (Request, error) {
	if req.FormValue("grant_type") != "client_credentials" {
		return nil, nil
	}

	clientId, clientSecret := resolveClientCredentials(req)
	scope := ScopeFromString(req.FormValue("scope"))
	return &ClientCredentialsRequest{
		clientId:     ClientId(clientId),
		clientSecret: clientSecret,
		scope:        scope,
	}, nil
}
