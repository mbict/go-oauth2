// Code generated by mockery v1.0.0
package mocks

import mock "github.com/stretchr/testify/mock"
import oauth2 "github.com/mbict/go-oauth2"
import time "time"
import url "net/url"

// Session is an autogenerated mock type for the Session type
type Session struct {
	mock.Mock
}

// ClientId provides a mock function with given fields:
func (_m *Session) ClientId() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// ExpiresAt provides a mock function with given fields:
func (_m *Session) ExpiresAt() time.Time {
	ret := _m.Called()

	var r0 time.Time
	if rf, ok := ret.Get(0).(func() time.Time); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Time)
	}

	return r0
}

// GrantScope provides a mock function with given fields: scopes
func (_m *Session) GrantScope(scopes ...string) {
	_va := make([]interface{}, len(scopes))
	for _i := range scopes {
		_va[_i] = scopes[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, _va...)
	_m.Called(_ca...)
}

// GrantedScopes provides a mock function with given fields:
func (_m *Session) GrantedScopes() oauth2.Scope {
	ret := _m.Called()

	var r0 oauth2.Scope
	if rf, ok := ret.Get(0).(func() oauth2.Scope); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(oauth2.Scope)
		}
	}

	return r0
}

// Id provides a mock function with given fields:
func (_m *Session) Id() oauth2.SessionId {
	ret := _m.Called()

	var r0 oauth2.SessionId
	if rf, ok := ret.Get(0).(func() oauth2.SessionId); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(oauth2.SessionId)
	}

	return r0
}

// RedirectUri provides a mock function with given fields:
func (_m *Session) RedirectUri() *url.URL {
	ret := _m.Called()

	var r0 *url.URL
	if rf, ok := ret.Get(0).(func() *url.URL); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*url.URL)
		}
	}

	return r0
}

// RequestValues provides a mock function with given fields:
func (_m *Session) RequestValues() url.Values {
	ret := _m.Called()

	var r0 url.Values
	if rf, ok := ret.Get(0).(func() url.Values); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(url.Values)
		}
	}

	return r0
}

// SetExpiresAt provides a mock function with given fields: expireAt
func (_m *Session) SetExpiresAt(expireAt time.Time) {
	_m.Called(expireAt)
}

// SetRedirectUri provides a mock function with given fields: _a0
func (_m *Session) SetRedirectUri(_a0 string) {
	_m.Called(_a0)
}

// SetRequestValues provides a mock function with given fields: values
func (_m *Session) SetRequestValues(values url.Values) {
	_m.Called(values)
}

// UserId provides a mock function with given fields:
func (_m *Session) UserId() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}
