package handler

import (
	"context"
	"github.com/mbict/go-oauth2"
)

type RevokeHandler struct {
	revokeTokenHandler *oauth2.RevokeTokenHandler
}

func NewRevokeHandler(clients oauth2.ClientStorage, tokens oauth2.TokenStorage) oauth2.Handler {
	return &RevokeHandler{
		revokeTokenHandler: oauth2.NewRevokeTokenHandler(clients, tokens, tokens, tokens),
	}
}

func (h *RevokeHandler) Handle(ctx context.Context, req oauth2.Request) (oauth2.Response, error) {
	switch t := req.(type) {
	case *oauth2.RevokeTokenRequest:
		return h.revokeTokenHandler.Handle(ctx, t)
	}
	return nil, oauth2.ErrInvalidRequest
}
