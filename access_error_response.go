package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

type AccessErrorResponse interface {
	Response
	OAuthError
}

type accessErrorResponse struct {
	OAuthError
}

func (r *accessErrorResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

	rfcerr := r.RFC6749()
	data, err := json.Marshal(rfcerr)
	if err != nil {
		http.Error(rw, fmt.Sprintf(`{"err": "%s"}`, strconv.Quote(err.Error())), http.StatusInternalServerError)
		return nil
	}

	rw.WriteHeader(rfcerr.Code)
	_, err = rw.Write(data)
	return err
}

func NewAccessErrorResponse(err OAuthError) AccessErrorResponse {
	return &accessErrorResponse{
		OAuthError: err,
	}
}
