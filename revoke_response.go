package oauth2

import (
	"context"
	"net/http"
	"net/url"
)

type RevokeTokenResponse struct {
}

func (*RevokeTokenResponse) RedirectUri() url.URL {
	panic("implement me")
}

func (*RevokeTokenResponse) AddQuery(name string, value string) {
	panic("implement me")
}

func (*RevokeTokenResponse) GetQuery(name string) string {
	panic("implement me")
}

func (f *RevokeTokenResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	rw.WriteHeader(http.StatusOK)
	return nil
}
