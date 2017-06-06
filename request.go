package oauth2

import (
	"net/url"
	"time"
)

type Request interface {
	RequestedAt() time.Time
	Client() Client
	Session() Session
	SetSession(Session)
	RequestValues() url.Values
	RequestedScopes() Scope
}

type request struct {
	requestedAt     time.Time
	client          Client
	session         Session
	requestValue    url.Values
	requestedScopes Scope
}

func (r *request) RequestedAt() time.Time {
	return r.requestedAt
}

func (r *request) Client() Client {
	return r.client
}

func (r *request) Session() Session {
	return r.session
}

func (r *request) SetSession(session Session) {
	r.session = session
}

func (r *request) RequestValues() url.Values {
	return r.requestValue
}

func (r *request) RequestedScopes() Scope {
	return r.requestedScopes
}

func newRequest(requestedAt time.Time, client Client, session Session, requestValues url.Values, requestedScopes Scope) Request {
	return &request{
		requestedAt:     requestedAt,
		client:          client,
		session:         session,
		requestValue:    requestValues,
		requestedScopes: requestedScopes,
	}
}
