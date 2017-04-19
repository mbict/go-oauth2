package flow

import (
	"context"
	"encoding/json"
	"github.com/mbict/go-oauth2"
	"net/http"
	"time"
)

type AccessTokenRequest struct {
	clientId     oauth2.ClientId
	clientSecret string
	code         string
	redirectUri  string
}

func (_ *AccessTokenRequest) Type() string {
	return "AccesToken"
}

func (_ *AccessTokenRequest) DecodeRequest(ctx context.Context, req *http.Request) (oauth2.Request, error) {
	if req.FormValue("grant_type") != "authorization_code" {
		return nil, nil
	}

	clientId, clientSecret := resolveClientCredentials(req)
	redirectUri := req.FormValue("redirect_uri")
	code := req.FormValue("code")
	return &AccessTokenRequest{
		clientId:     oauth2.ClientId(clientId),
		clientSecret: clientSecret,
		code:         code,
		redirectUri:  redirectUri,
	}, nil
}

type AccessTokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    time.Duration
	RefreshToken string

	Data map[string]interface{}
}

func (r *AccessTokenResponse) AddData(key string, value interface{}) {
	r.Data[key] = value
}

func (r *AccessTokenResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")
	rw.WriteHeader(http.StatusOK)

	jenc := json.NewEncoder(rw)
	return jenc.Encode(r.toMap())
}

func (r *AccessTokenResponse) toMap() map[string]interface{} {
	data := make(map[string]interface{})

	data["access_token"] = r.AccessToken
	data["token_type"] = r.TokenType
	data["expires_in"] = int(r.ExpiresIn.Seconds())

	if r.RefreshToken != "" {
		data["refresh_token"] = r.RefreshToken
	}

	//copy data into map
	for k, v := range r.Data {
		data[k] = v
	}

	return data
}

type AccessTokenFlow struct {
	clients       oauth2.ClientStorage
	codes         oauth2.AuthorizeCodeStorage
	accessTokens  oauth2.AccessTokenStorage
	refreshTokens oauth2.RefreshTokenStorage
}

func (f *AccessTokenFlow) Handle(ctx context.Context, req *AccessTokenRequest) (oauth2.Response, error) {
	//authenticate client credentials
	client, err := f.clients.AuthenticateClient(req.clientId, req.clientSecret)
	if err != nil {
		return nil, oauth2.ErrUnauthorizedClient
	}

	//check if code session exists for this client id
	code, err := f.codes.GetAuthorizeCodeSession(req.code)
	if err != nil || code.ClientId() != client.ClientId() {
		return nil, oauth2.ErrInvalidRequest
	}

	//check if the redirect uri matches the request
	if code.RedirectUri() != req.redirectUri {
		return nil, oauth2.ErrInvalidRequest
	}

	//ok we remove the code token

	//ok we create new access token

	//ok we create new refresh token

	//create new access token
	accessToken := ""
	refreshToken := ""
	expiresIn := time.Hour * 24

	resp := &AccessTokenResponse{
		AccessToken:  accessToken,
		TokenType:    "resource_owner",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
	}

	return resp, nil
}

func NewAccessTokenHandler(
	clients oauth2.ClientStorage,
	codes oauth2.AuthorizeCodeStorage,
	accessTokens oauth2.AccessTokenStorage,
	refreshTokens oauth2.RefreshTokenStorage) *AccessTokenFlow {
	return &AccessTokenFlow{
		clients:       clients,
		codes:         codes,
		accessTokens:  accessTokens,
		refreshTokens: refreshTokens,
	}
}
