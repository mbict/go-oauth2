// Code generated by mockery v1.0.0
package mocks

import mock "github.com/stretchr/testify/mock"
import oauth2 "github.com/mbict/go-oauth2"
import time "time"
import url "net/url"

// Request is an autogenerated mock type for the Request type
type Request struct {
	mock.Mock
}

// Client provides a mock function with given fields:
func (_m *Request) Client() oauth2.Client {
	ret := _m.Called()

	var r0 oauth2.Client
	if rf, ok := ret.Get(0).(func() oauth2.Client); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(oauth2.Client)
		}
	}

	return r0
}

// GrantScope provides a mock function with given fields: scope
func (_m *Request) GrantScope(scope ...string) {
	_va := make([]interface{}, len(scope))
	for _i := range scope {
		_va[_i] = scope[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, _va...)
	_m.Called(_ca...)
}

// GrantedScopes provides a mock function with given fields:
func (_m *Request) GrantedScopes() oauth2.Scope {
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

// RequestValues provides a mock function with given fields:
func (_m *Request) RequestValues() url.Values {
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

// RequestedAt provides a mock function with given fields:
func (_m *Request) RequestedAt() time.Time {
	ret := _m.Called()

	var r0 time.Time
	if rf, ok := ret.Get(0).(func() time.Time); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Time)
	}

	return r0
}

// RequestedScopes provides a mock function with given fields:
func (_m *Request) RequestedScopes() oauth2.Scope {
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

// Session provides a mock function with given fields:
func (_m *Request) Session() oauth2.Session {
	ret := _m.Called()

	var r0 oauth2.Session
	if rf, ok := ret.Get(0).(func() oauth2.Session); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(oauth2.Session)
		}
	}

	return r0
}
