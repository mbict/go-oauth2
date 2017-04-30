package oauth2

import (
	"context"
	"net/http"
	"strings"
)

type ResourceOwnerRequest struct {
	clientId     ClientId
	clientSecret string
	username     string
	password     string
	scope        []string
}

func (_ *ResourceOwnerRequest) DecodeRequest(ctx context.Context, req *http.Request) (Request, error) {
	if req.FormValue("grant_type") != "password" {
		return nil, nil
	}

	clientId, clientSecret := resolveClientCredentials(req)
	username := req.PostFormValue("username")
	password := req.PostFormValue("password")
	scope := strings.Split(req.FormValue("scope"), " ")
	return &ResourceOwnerRequest{
		clientId:     ClientId(clientId),
		clientSecret: clientSecret,
		username:     username,
		password:     password,
		scope:        scope,
	}, nil
}
