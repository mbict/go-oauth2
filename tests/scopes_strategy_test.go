package tests

import (
	. "github.com/mbict/go-oauth2"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDefaultScopeStrategy(t *testing.T) {
	var testcases = map[string]struct {
		scopes   Scope
		needle   Scope
		expected bool
	}{
		"empty":        {Scope{}, Scope{}, true},
		"empty needle": {Scope{"foo"}, Scope{}, true},
		"empty scope":  {Scope{}, Scope{"foo"}, false},
		"match":        {Scope{"foo", "bar"}, Scope{"foo"}, true},
		"partial match does not count": {Scope{"foobar"}, Scope{"foo"}, false},
		"empty needle string ignored":  {Scope{"foobar"}, Scope{""}, true},
	}

	for test, tc := range testcases {
		t.Logf("Test case %s", test)

		res := DefaultScopeStrategy(tc.scopes, tc.needle...)

		assert.EqualValues(t, tc.expected, res, "[%s] expected %v as result but got %v", test, tc.expected, res)
	}
}
