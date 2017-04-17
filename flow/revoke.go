package flow

import (
	"context"
	"github.com/mbict/go-oauth2"
	"net/http"
)

type RevokeTokenRequest struct {
	clientId     oauth2.ClientId
	clientSecret string
	token        string
	tokenType    string
}

func (_ *RevokeTokenRequest) Type() string {
	return "Revoke"
}

func (_ *RevokeTokenRequest) DecodeRequest(ctx context.Context, req *http.Request) (oauth2.Request, error) {
	if req.FormValue("grant_type") != "password" {
		return nil, nil
	}

	clientId, clientSecret := resolveClientCredentials(req)
	token := req.PostFormValue("token")
	tokenType := req.PostFormValue("token_type")
	return &RevokeTokenRequest{
		clientId:     oauth2.ClientId(clientId),
		clientSecret: clientSecret,
		token:        token,
		tokenType:    tokenType,
	}, nil
}

type RevokeTokenResponse struct {
}

func (f *RevokeTokenResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	rw.WriteHeader(http.StatusOK)
	return nil
}

type RevokeTokenFlow struct {
	clients        oauth2.ClientStorage
	authorizeCodes oauth2.AuthorizeCodeStorage
	accessTokens   oauth2.AccessTokenStorage
	refreshTokens  oauth2.RefreshTokenStorage
}

func (f *RevokeTokenFlow) Handle(ctx context.Context, req *RevokeTokenRequest) (oauth2.Response, error) {
	//authenticate client credentials
	_, err := f.clients.Authenticate(req.clientId, req.clientSecret)
	if err != nil {
		return nil, oauth2.ErrUnauthorizedClient
	}

	//check if there is no unsupported toke type requested
	if req.tokenType != "" &&
		req.tokenType != "authorize_code" &&
		req.tokenType != "refresh_token" &&
		req.tokenType != "access_token" {
		return nil, oauth2.ErrUnsupportedTokenType
	}

	//revoke authorize code
	if req.tokenType == "" || req.tokenType == "authorize_code" {
		_, err := f.authorizeCodes.DeleteAuthorizeCodeSession(req.token)
		if err != nil && err != oauth2.ErrCodeNotFound {
			return nil, err
		}
	}

	//revoke refresh token
	if req.tokenType == "" || req.tokenType == "refresh_token" {
		_, err := f.refreshTokens.DeleteRefreshTokenSession(req.token)
		if err != nil && err != oauth2.ErrTokenNotFound {
			return nil, err
		}
	}

	//revoke access token
	if req.tokenType == "" || req.tokenType == "access_token" {
		_, err := f.accessTokens.DeleteAccessTokenSession(req.token)
		if err != nil && err != oauth2.ErrTokenNotFound {
			return nil, err
		}
	}

	return &RevokeTokenResponse{}, nil
}

func NewRevokeTokenHandler(clients oauth2.ClientStorage, authorizeCodes oauth2.AuthorizeCodeStorage, accessTokens oauth2.AccessTokenStorage, refreshTokens oauth2.RefreshTokenStorage) *RevokeTokenFlow {
	return &RevokeTokenFlow{
		clients:        clients,
		authorizeCodes: authorizeCodes,
		accessTokens:   accessTokens,
		refreshTokens:  refreshTokens,
	}
}
