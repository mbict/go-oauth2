package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

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
