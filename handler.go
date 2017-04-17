package oauth2

import "context"

type Handler interface {
	Handle(ctx context.Context, req Request) (Response, error)
}
