package oauth2

import (
//"context"
//"net/url"
)

//type ConsentStrategyFunc func(context.Context, *AuthorizeRequest) (Response, error)
//
////NewConsentRedirectStrategy creates a default redirection strategy and append all the data to the url
//func NewConsentRedirectStrategy(uri string) ConsentStrategyFunc {
//	baseUrl, err := url.Parse(uri)
//	if err != nil {
//		panic(err)
//	}
//	return func(ctx context.Context, r *AuthorizeRequest) (Response, error) {
//		redirectUri := *baseUrl
//		q := map[string]string{
//			"client_id":     string(r.ClientId),
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
//			Error:       nil, //ErrNeedConsent
//			RedirectUri: &redirectUri,
//			Query:       q,
//		}, nil
//	}
//}
