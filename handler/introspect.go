package handler

import (
	"context"
	"github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/flow"
)

type IntrospectHandler struct {
	revokeTokenFlow *flow.IntrospectFlow
}

func NewIntrospectHandler() oauth2.Handler {
	return &IntrospectHandler{
		revokeTokenFlow: flow.NewIntrospectHandler(),
	}

}

func (h *IntrospectHandler) Handle(ctx context.Context, req oauth2.Request) (oauth2.Response, error) {
	switch t := req.(type) {
	case *flow.IntrospectRequest:
		return h.revokeTokenFlow.Handle(ctx, t)
	}
	return nil, oauth2.ErrInvalidRequest
}
