package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type AccessTokenResponse interface {
	Response

	AccessToken() string
	TokenType() string
	ExpiresIn() time.Duration
	RefreshToken() string

	AddData(key string, value interface{})
}

type accessTokenResponse struct {
	accessToken  string
	tokenType    string
	expiresIn    time.Duration
	refreshToken string

	data map[string]interface{}
}

func (r *accessTokenResponse) AccessToken() string {
	return r.accessToken
}

func (r *accessTokenResponse) TokenType() string {
	return r.tokenType
}

func (r *accessTokenResponse) ExpiresIn() time.Duration {
	return r.expiresIn
}

func (r *accessTokenResponse) RefreshToken() string {
	return r.refreshToken
}

func (r *accessTokenResponse) AddData(key string, value interface{}) {
	r.data[key] = value
}

func (r *accessTokenResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")
	rw.WriteHeader(http.StatusOK)

	jenc := json.NewEncoder(rw)
	return jenc.Encode(r.toMap())
}

func (r *accessTokenResponse) toMap() map[string]interface{} {
	data := make(map[string]interface{})

	data["access_token"] = r.accessToken
	data["token_type"] = r.tokenType
	data["expires_in"] = int(r.expiresIn.Seconds())

	if r.refreshToken != "" {
		data["refresh_token"] = r.refreshToken
	}

	//copy data into map
	for k, v := range r.data {
		data[k] = v
	}

	return data
}
