// Code generated by mockery v1.0.0
package mocks

import context "context"
import mock "github.com/stretchr/testify/mock"
import oauth2 "github.com/mbict/go-oauth2"

// AccessTokenStorage is an autogenerated mock type for the AccessTokenStorage type
type AccessTokenStorage struct {
	mock.Mock
}

// CreateAccessTokenSession provides a mock function with given fields: ctx, signature, req
func (_m *AccessTokenStorage) CreateAccessTokenSession(ctx context.Context, signature string, req oauth2.Request) error {
	ret := _m.Called(ctx, signature, req)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, oauth2.Request) error); ok {
		r0 = rf(ctx, signature, req)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteAccessTokenSession provides a mock function with given fields: ctx, signature
func (_m *AccessTokenStorage) DeleteAccessTokenSession(ctx context.Context, signature string) (bool, error) {
	ret := _m.Called(ctx, signature)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, string) bool); ok {
		r0 = rf(ctx, signature)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, signature)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAccessTokenSession provides a mock function with given fields: ctx, signature
func (_m *AccessTokenStorage) GetAccessTokenSession(ctx context.Context, signature string) (oauth2.Session, error) {
	ret := _m.Called(ctx, signature)

	var r0 oauth2.Session
	if rf, ok := ret.Get(0).(func(context.Context, string) oauth2.Session); ok {
		r0 = rf(ctx, signature)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(oauth2.Session)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, signature)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
