package oauth2

import (
	"context"
	"net/http"
)

type SessionResolverFunc func(context.Context, *http.Request) (Session, error)

var SessionCookieId = "ssid"

// NewSessionResolver creates asimple session resolver who queries the session storage to find a session
// The session should be found trough the ssid key
func NewSessionResolver(sessions SessionStorage) SessionResolverFunc {
	return func(ctx context.Context, r *http.Request) (Session, error) {
		ssid, err := r.Cookie(SessionCookieId)
		if err != nil || ssid == nil {
			return nil, nil
		}
		return sessions.GetSession(SessionId(ssid.Value))
	}
}
