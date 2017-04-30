package oauth2

import (
	"context"
	"net/http"
	"strings"
)

type RefreshRequest struct {
	clientId     ClientId
	clientSecret string
	refreshToken string
	scope        []string //optional
}

func (_ *RefreshRequest) DecodeRequest(ctx context.Context, req *http.Request) (Request, error) {
	if req.FormValue("grant_type") != "refresh_token" {
		return nil, nil
	}

	clientId, clientSecret := resolveClientCredentials(req)
	refreshToken := req.PostFormValue("refresh_token")
	scope := strings.Split(req.FormValue("scope"), " ")

	return &RefreshRequest{
		clientId:     ClientId(clientId),
		clientSecret: clientSecret,
		refreshToken: refreshToken,
		scope:        scope,
	}, nil
}
