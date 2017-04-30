package handler

import (
	"context"
	"github.com/mbict/go-oauth2"
)

type IntrospectHandler struct {
	revokeTokenHandler *oauth2.IntrospectHandler
}

func NewIntrospectHandler(clients oauth2.ClientStorage, tokens oauth2.TokenStorage) oauth2.Handler {
	return &IntrospectHandler{
		revokeTokenHandler: oauth2.NewIntrospectHandler(clients, tokens, tokens),
	}

}

func (h *IntrospectHandler) Handle(ctx context.Context, req oauth2.Request) (oauth2.Response, error) {
	switch t := req.(type) {
	case *oauth2.IntrospectRequest:
		return h.revokeTokenHandler.Handle(ctx, t)
	}
	return nil, oauth2.ErrInvalidRequest
}
