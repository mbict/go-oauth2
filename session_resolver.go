package oauth2

import (
//"context"
//"net/http"
)

// UserSessionResolver should resolve the user_id used inside the session
// type UserSessionResolver func(context.Context, *http.Request) (string, error)

// var SessionCookieId = "ssid"

// NewSessionResolver creates a simple way to resolve user session based on a cookie
//func NewUserSessionResolver(sessions SessionResolverStorage) UserSessionResolver {
//	return func(ctx context.Context, s *http.Request) (Session, error) {
//		ssid, err := s.Cookie(SessionCookieId)
//		if err != nil || ssid == nil {
//			return nil, nil
//		}
//		return sessions.GetSession(SessionId(ssid.Value))
//	}
//}
