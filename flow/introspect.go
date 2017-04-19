package flow

import (
	"context"
	"encoding/json"
	"github.com/mbict/go-oauth2"
	"net/http"
	"strconv"
)

type IntrospectRequest struct {
	clientId     oauth2.ClientId
	clientSecret string
	token        string
	tokenType    oauth2.TokenType
}

func (_ *IntrospectRequest) Type() string {
	return "Introspect"
}

func (_ *IntrospectRequest) DecodeRequest(ctx context.Context, req *http.Request) (oauth2.Request, error) {
	if req.FormValue("grant_type") != "password" {
		return nil, nil
	}

	clientId, clientSecret := resolveClientCredentials(req)
	token := req.PostFormValue("token")
	tokenType := req.PostFormValue("token_type")
	return &IntrospectRequest{
		clientId:     oauth2.ClientId(clientId),
		clientSecret: clientSecret,
		token:        token,
		tokenType:    oauth2.TokenType(tokenType),
	}, nil
}

type IntrospectResponse struct {
	Active    bool
	Scope     oauth2.Scope
	ClientId  oauth2.ClientId
	Username  string
	TokenType oauth2.TokenType

	Data map[string]interface{}
}

func (r *IntrospectResponse) AddData(key string, value interface{}) {
	r.Data[key] = value
}

func (r *IntrospectResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
	rw.WriteHeader(http.StatusOK)

	jenc := json.NewEncoder(rw)
	return jenc.Encode(r.toMap())
}

func (r *IntrospectResponse) toMap() map[string]interface{} {
	data := make(map[string]interface{})

	data["active"] = strconv.FormatBool(r.Active)

	if r.Active == true {
		if len(r.Scope) > 0 {
			data["scope"] = r.Scope
		}

		if r.TokenType != "" {
			data["token_type"] = r.TokenType
		}

		if r.ClientId != "" {
			data["client_id"] = r.ClientId
		}

		if r.Username != "" {
			data["username"] = r.Username
		}

		//copy data into map
		for k, v := range r.Data {
			data[k] = v
		}
	}
	return data
}

type IntrospectFlow struct {
	clients       oauth2.ClientStorage
	accessTokens  oauth2.AccessTokenStorage
	refreshTokens oauth2.RefreshTokenStorage
}

func (f *IntrospectFlow) Handle(ctx context.Context, req *IntrospectRequest) (oauth2.Response, error) {
	//authenticate client credentials
	_, err := f.clients.AuthenticateClient(req.clientId, req.clientSecret)
	if err != nil {
		return nil, oauth2.ErrUnauthorizedClient
	}

	var token oauth2.Token
	if req.tokenType == "" || req.tokenType == "access_token" {
		token, err = f.accessTokens.GetAccessTokenSession(req.token)
		if err != nil {
			return nil, oauth2.ErrInvalidRequest
		}
	}

	if req.tokenType == "" || req.tokenType == "refresh_token" {
		token, err = f.refreshTokens.GetRefreshTokenSession(req.token)
		if err != nil {
			return nil, oauth2.ErrInvalidRequest
		}
	}

	if token == nil {
		return &IntrospectResponse{
			Active: false,
		}, nil
	}

	//if we got a user session we provide the username
	username := ""
	if token.Session() != nil {
		username = token.Session().Username()
	}

	return &IntrospectResponse{
		Active:    true,
		Scope:     token.Scope(),
		TokenType: token.Type(),
		Username:  username,
		ClientId:  token.ClientId(),
	}, nil
}

func NewIntrospectHandler(clients oauth2.ClientStorage, accessTokens oauth2.AccessTokenStorage, refreshTokens oauth2.RefreshTokenStorage) *IntrospectFlow {
	return &IntrospectFlow{
		clients:       clients,
		accessTokens:  accessTokens,
		refreshTokens: refreshTokens,
	}

}
