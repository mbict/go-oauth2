package oauth2

import (
	"context"
	"net/http"
)

type AccessTokenRequest struct {
	clientId     ClientId
	clientSecret string
	code         string
	redirectUri  string
}

func (_ *AccessTokenRequest) DecodeRequest(ctx context.Context, req *http.Request) (Request, error) {
	if req.FormValue("grant_type") != "authorization_code" {
		return nil, nil
	}

	clientId, clientSecret := resolveClientCredentials(req)
	redirectUri := req.FormValue("redirect_uri")
	code := req.FormValue("code")
	return &AccessTokenRequest{
		clientId:     ClientId(clientId),
		clientSecret: clientSecret,
		code:         code,
		redirectUri:  redirectUri,
	}, nil
}
