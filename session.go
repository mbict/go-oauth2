package oauth2

import (
	"github.com/satori/go.uuid"
	"net/url"
	"time"
)

type SessionId string

type Session interface {
	Id() SessionId
	ClientId() ClientId
	GrantedScopes() Scope
	GrantScope(scopes ...string)
	UserId() string
	ExpiresAt() time.Time
	SetExpiresAt(expireAt time.Time)
	RequestValues() url.Values
	SetRequestValues(values url.Values)
	RedirectUri() *url.URL
	SetRedirectUri(url string)
}

type session struct {
	id            SessionId
	clientId      ClientId
	userId        string
	expiresAt     time.Time
	grantedScopes Scope
	requestValues url.Values
}

func (s *session) ClientId() ClientId {
	return s.clientId
}

func (s *session) Id() SessionId {
	return s.id
}

func (s *session) UserId() string {
	return s.userId
}

func (s *session) ExpiresAt() time.Time {
	return s.expiresAt
}

func (s *session) SetExpiresAt(expireAt time.Time) {
	s.expiresAt = expireAt
}

func (s *session) GrantedScopes() Scope {
	return s.grantedScopes
}

func (s *session) GrantScope(scopes ...string) {
	for _, scope := range scopes {
		if s.grantedScopes.Has(Scope{scope}) == true {
			continue
		}
		s.grantedScopes = append(s.grantedScopes, scope)
	}
}

func (s *session) RequestValues() url.Values {
	return s.requestValues
}

func (s *session) SetRequestValues(values url.Values) {
	s.requestValues = values
}

func (s *session) RedirectUri() *url.URL {
	if s.requestValues.Get("redirect_uri") == "" {
		return nil
	}
	u, _ := url.Parse(s.requestValues.Get("redirect_uri"))
	return u
}

func (s *session) SetRedirectUri(url string) {
	s.requestValues.Set("redirect_uri", url)
}

func NewSession(userId string, clientId ClientId) Session {
	return &session{
		id:       SessionId(uuid.NewV4().String()),
		userId:   userId,
		clientId: clientId,
	}
}
