package oauth2

import (
	"context"
	"net/http"
)

type Response interface {
	EncodeResponse(context.Context, http.ResponseWriter) error
}
