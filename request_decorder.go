package oauth2

import (
	"context"
	"net/http"
)

type RequestDecoder func(context.Context, *http.Request) (Request, error)

type requestDecoder []RequestDecoder

func (d requestDecoder) DecodeRequest(ctx context.Context, req *http.Request) (Request, error) {
	for _, decoder := range d {
		if r, err := decoder(ctx, req); r != nil || err != nil {
			return r, err
		}
	}
	return nil, ErrInvalidRequest
}

func NewRequestDecoder(decoders ...RequestDecoder) RequestDecoder {
	return requestDecoder(decoders).DecodeRequest
}
