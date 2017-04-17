package flow

import (
	"context"
	"github.com/mbict/go-oauth2"
	"net/http"
	"strings"
	"time"
)

type RefreshRequest struct {
	clientId     oauth2.ClientId
	clientSecret string
	refreshToken string
	scope        []string //optional
}

func (_ *RefreshRequest) Type() string {
	return "Refresh"
}

func (_ *RefreshRequest) DecodeRequest(ctx context.Context, req *http.Request) (oauth2.Request, error) {
	if req.FormValue("grant_type") != "refresh_token" {
		return nil, nil
	}

	clientId, clientSecret := resolveClientCredentials(req)
	refreshToken := req.PostFormValue("refresh_token")
	scope := strings.Split(req.FormValue("scope"), " ")

	return &RefreshRequest{
		clientId:     oauth2.ClientId(clientId),
		clientSecret: clientSecret,
		refreshToken: refreshToken,
		scope:        scope,
	}, nil
}

type RefreshFlow struct {
	clients       oauth2.ClientStorage
	refreshTokens oauth2.RefreshTokenStorage
	accessTokens  oauth2.AccessTokenStorage
}

func (f *RefreshFlow) Handle(ctx context.Context, req *RefreshRequest) (oauth2.Response, error) {
	//authenticate client credentials
	client, err := f.clients.Authenticate(req.clientId, req.clientSecret)
	if err != nil {
		return nil, oauth2.ErrUnauthorizedClient
	}

	//get the refresh token from storage
	token, err := f.refreshTokens.GetRefreshTokenSession(req.refreshToken)
	if err != nil || token.ClientId != client.ClientId {
		return nil, oauth2.ErrInvalidRequest
	}

	//check if all the scopes are valid
	if !token.Scope.Has(req.scope) {
		return nil, oauth2.ErrInvalidScope
	}

	//issue a new access token
	accessToken := ""
	expiresIn := time.Hour * 24

	//create a new refresh token if the scope differs from the stored refresh scope
	refreshToken := ""

	resp := &AccessTokenResponse{
		AccessToken:  accessToken,
		TokenType:    "resource_owner",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
	}

	return resp, nil
}

func NewRefreshHandler(clients oauth2.ClientStorage, refreshTokens oauth2.RefreshTokenStorage, accessTokens oauth2.AccessTokenStorage) *RefreshFlow {
	return &RefreshFlow{
		clients:       clients,
		refreshTokens: refreshTokens,
		accessTokens:  accessTokens,
	}
}
