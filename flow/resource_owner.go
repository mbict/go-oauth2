package flow

import (
	"context"
	"github.com/mbict/go-oauth2"
	"net/http"
	"strings"
	"time"
)

type ResourceOwnerRequest struct {
	clientId     oauth2.ClientId
	clientSecret string
	username     string
	password     string
	scope        []string
}

func (_ *ResourceOwnerRequest) Type() string {
	return "ResourceOwner"
}

func (_ *ResourceOwnerRequest) DecodeRequest(ctx context.Context, req *http.Request) (oauth2.Request, error) {
	if req.FormValue("grant_type") != "password" {
		return nil, nil
	}

	clientId, clientSecret := resolveClientCredentials(req)
	username := req.PostFormValue("username")
	password := req.PostFormValue("password")
	scope := strings.Split(req.FormValue("scope"), " ")
	return &ResourceOwnerRequest{
		clientId:     oauth2.ClientId(clientId),
		clientSecret: clientSecret,
		username:     username,
		password:     password,
		scope:        scope,
	}, nil
}

type ResourceOwnerFlow struct {
	clients      oauth2.ClientStorage
	users        oauth2.UserStorage
	sessions     oauth2.SessionStorage
	accessTokens oauth2.AccessTokenStorage
}

func (f *ResourceOwnerFlow) Handle(ctx context.Context, req *ResourceOwnerRequest) (oauth2.Response, error) {

	//authenticate client credentials
	client, err := f.clients.Authenticate(req.clientId, req.clientSecret)
	if err != nil {
		return nil, oauth2.ErrUnauthorizedClient
	}

	user, err := f.users.Authenticate(req.username, req.password)
	if err != nil {
		return nil, oauth2.ErrUnauthorizedClient
	}

	//check if all the scopes are there
	if !client.Scope.Has(req.scope) {
		return nil, oauth2.ErrInvalidScope
	}

	//create a session for the authenticated user
	//f.sessions.NewSession()

	//create new access token
	token := ""
	expiresIn := time.Hour * 24

	resp := &AccessTokenResponse{
		AccessToken: token,
		TokenType:   "resource_owner",
		ExpiresIn:   expiresIn,
	}

	return resp, nil
}

func NewResourceOwnerHandler(clients oauth2.ClientStorage, users oauth2.UserStorage, sessions oauth2.SessionStorage, accessTokens oauth2.AccessTokenStorage) *ResourceOwnerFlow {
	return &ResourceOwnerFlow{
		clients:      clients,
		users:        users,
		sessions:     sessions,
		accessTokens: accessTokens,
	}
}
