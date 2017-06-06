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
//	return func(ctx context.Context, s *AuthorizeRequest) (Response, error) {
//		redirectUri := *baseUrl
//		q := map[string]string{
//			"client_id":     string(s.ClientId),
//			"response_type": s.responseTypes.String(),
//			"redirect_uri":  s.RedirectUri.String(),
//		}
//
//		if len(s.Scope) > 0 {
//			q["scope"] = s.Scope.String()
//		}
//		if s.state != "" {
//			q["state"] = s.state
//		}
//
//		return &ErrorResponse{
//			Error:       nil, //ErrNeedConsent
//			RedirectUri: &redirectUri,
//			Query:       q,
//		}, nil
//	}
//}
