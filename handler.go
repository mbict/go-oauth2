package oauth2

import "context"

type Handler interface {
	Handle(ctx context.Context, req Request) (Response, error)
}

type AuthorizeHandler interface {
	Handle(ctx context.Context, req AuthorizeRequest, resp AuthorizeResponse) (bool, error)
}
