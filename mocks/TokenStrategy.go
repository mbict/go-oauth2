// Code generated by mockery v1.0.0
package mocks

import context "context"
import mock "github.com/stretchr/testify/mock"
import oauth2 "github.com/mbict/go-oauth2"
import time "time"

// TokenStrategy is an autogenerated mock type for the TokenStrategy type
type TokenStrategy struct {
	mock.Mock
}

// AccessTokenLifespan provides a mock function with given fields:
func (_m *TokenStrategy) AccessTokenLifespan() time.Duration {
	ret := _m.Called()

	var r0 time.Duration
	if rf, ok := ret.Get(0).(func() time.Duration); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Duration)
	}

	return r0
}

// AccessTokenSignature provides a mock function with given fields: token
func (_m *TokenStrategy) AccessTokenSignature(token string) (string, error) {
	ret := _m.Called(token)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(token)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AuthorizeCodeLifespan provides a mock function with given fields:
func (_m *TokenStrategy) AuthorizeCodeLifespan() time.Duration {
	ret := _m.Called()

	var r0 time.Duration
	if rf, ok := ret.Get(0).(func() time.Duration); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Duration)
	}

	return r0
}

// AuthorizeCodeSignature provides a mock function with given fields: token
func (_m *TokenStrategy) AuthorizeCodeSignature(token string) (string, error) {
	ret := _m.Called(token)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(token)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GenerateAccessToken provides a mock function with given fields: ctx, session
func (_m *TokenStrategy) GenerateAccessToken(ctx context.Context, session oauth2.Session) (string, string, error) {
	ret := _m.Called(ctx, session)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, oauth2.Session) string); ok {
		r0 = rf(ctx, session)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 string
	if rf, ok := ret.Get(1).(func(context.Context, oauth2.Session) string); ok {
		r1 = rf(ctx, session)
	} else {
		r1 = ret.Get(1).(string)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, oauth2.Session) error); ok {
		r2 = rf(ctx, session)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GenerateAuthorizeCode provides a mock function with given fields: ctx, session
func (_m *TokenStrategy) GenerateAuthorizeCode(ctx context.Context, session oauth2.Session) (string, string, error) {
	ret := _m.Called(ctx, session)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, oauth2.Session) string); ok {
		r0 = rf(ctx, session)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 string
	if rf, ok := ret.Get(1).(func(context.Context, oauth2.Session) string); ok {
		r1 = rf(ctx, session)
	} else {
		r1 = ret.Get(1).(string)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, oauth2.Session) error); ok {
		r2 = rf(ctx, session)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GenerateRefreshToken provides a mock function with given fields: ctx, session
func (_m *TokenStrategy) GenerateRefreshToken(ctx context.Context, session oauth2.Session) (string, string, error) {
	ret := _m.Called(ctx, session)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, oauth2.Session) string); ok {
		r0 = rf(ctx, session)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 string
	if rf, ok := ret.Get(1).(func(context.Context, oauth2.Session) string); ok {
		r1 = rf(ctx, session)
	} else {
		r1 = ret.Get(1).(string)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, oauth2.Session) error); ok {
		r2 = rf(ctx, session)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// RefreshTokenSignature provides a mock function with given fields: token
func (_m *TokenStrategy) RefreshTokenSignature(token string) (string, error) {
	ret := _m.Called(token)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(token)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidateAccessToken provides a mock function with given fields: ctx, session, token
func (_m *TokenStrategy) ValidateAccessToken(ctx context.Context, session oauth2.Session, token string) error {
	ret := _m.Called(ctx, session, token)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, oauth2.Session, string) error); ok {
		r0 = rf(ctx, session, token)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ValidateAuthorizeCode provides a mock function with given fields: ctx, session, token
func (_m *TokenStrategy) ValidateAuthorizeCode(ctx context.Context, session oauth2.Session, token string) error {
	ret := _m.Called(ctx, session, token)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, oauth2.Session, string) error); ok {
		r0 = rf(ctx, session, token)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ValidateRefreshToken provides a mock function with given fields: ctx, session, token
func (_m *TokenStrategy) ValidateRefreshToken(ctx context.Context, session oauth2.Session, token string) error {
	ret := _m.Called(ctx, session, token)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, oauth2.Session, string) error); ok {
		r0 = rf(ctx, session, token)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
