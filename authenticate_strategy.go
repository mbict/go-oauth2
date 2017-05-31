package oauth2

import (
	"context"
)

type AuthenticateStrategyFunc func(context.Context, *AuthorizeRequest) (Response, error)

//NewAutenticateRedirectStrategy will redirect to the given uri and append all the query data to the url
// This strategy will will be invoked if there is no user session active.
//func NewAuthenticateRedirectStrategy(uri string) AuthenticateStrategyFunc {
//	baseUrl, err := url.Parse(uri)
//	if err != nil {
//		panic(err)
//	}
//	return func(ctx context.Context, r *AuthorizeRequest) (Response, error) {
//		redirectUri := *baseUrl
//		q := map[string]string{
//			"client_id":     string(r.Client().ClientId()),
//			"response_type": r.responseTypes.String(),
//			"redirect_uri":  r.RedirectUri.String(),
//		}
//
//		if len(r.Scope) > 0 {
//			q["scope"] = r.Scope.String()
//		}
//		if r.state != "" {
//			q["state"] = r.state
//		}
//
//		return &ErrorResponse{
//			Error:       nil, //ErrNeedAuthorizedUser
//			RedirectUri: &redirectUri,
//			Query:       q,
//		}, nil
//	}
//}
