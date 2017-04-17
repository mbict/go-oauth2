package handler

import (
	"context"
	"github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/flow"
)

type RevokeHandler struct {
	revokeTokenFlow *flow.RevokeTokenFlow
}

func NewRevokeHandler() oauth2.Handler {
	return &RevokeHandler{
		revokeTokenFlow: flow.NewRevokeTokenHandler(),
	}

}

func (h *RevokeHandler) Handle(ctx context.Context, req oauth2.Request) (oauth2.Response, error) {
	switch t := req.(type) {
	case *flow.RevokeTokenRequest:
		return h.revokeTokenFlow.Handle(ctx, t)
	}
	return nil, oauth2.ErrInvalidRequest
}
