package oauth2

import (
	"net/url"
	"time"
)

type Request interface {
	RequestedAt() time.Time
	Client() Client
	Session() Session
	RequestValues() url.Values
	RequestedScopes() Scope
	GrantedScopes() Scope
	GrantScope(scope ...string)
}

type request struct {
	requestedAt     time.Time
	client          Client
	session         Session
	requestValue    url.Values
	requestedScopes Scope
	grantedScopes   Scope
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

func (r *request) RequestValues() url.Values {
	return r.requestValue
}

func (r *request) RequestedScopes() Scope {
	return r.requestedScopes
}

func (r *request) GrantedScopes() Scope {
	return r.grantedScopes
}

func (r *request) GrantScope(scopes ...string) {
	for _, scope := range scopes {
		if r.grantedScopes.Has(Scope{scope}) == true {
			continue
		}
		r.grantedScopes = append(r.grantedScopes, scope)
	}
}
