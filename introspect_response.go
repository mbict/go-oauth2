package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

type IntrospectResponse struct {
	Active   bool
	Scope    Scope
	ClientId ClientId
	Username string
	//tokenType tokenType

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

		//if s.TokenType != "" {
		//	data["token_type"] = s.TokenType
		//}

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
