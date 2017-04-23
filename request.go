package oauth2

import (
	"context"
	"net/http"
)

type RequestDecoder interface {
	DecodeRequest(context.Context, *http.Request) (Request, error)
}

type Request interface {
	RequestDecoder
}

type requestDecoder struct {
	decoders []Request
}

func (d *requestDecoder) DecodeRequest(ctx context.Context, req *http.Request) (Request, error) {
	for _, decoder := range d.decoders {
		if r, err := decoder.DecodeRequest(ctx, req); r != nil || err != nil {
			return r, err
		}
	}
	return nil, ErrInvalidRequest
}

func NewRequestDecoder(decoders ...Request) RequestDecoder {
	return &requestDecoder{
		decoders: decoders,
	}
}
