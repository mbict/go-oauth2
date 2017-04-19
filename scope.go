package oauth2

import (
	"strings"
)

type Scope []string

// Has compares the current cope with the provided scope if all values intersect
func (s Scope) Has(scope Scope) bool {
	hasScope := func(a string) bool {
		for _, b := range s {
			if a == b {
				return true
			}
		}
		return false
	}

	for _, a := range scope {
		if !hasScope(a) {
			return false
		}
	}
	return true
}

func (s Scope) String() string {
	return strings.Join(s, " ")
}

// ScopeFromString creates a new scope from a space delimited string
func ScopeFromString(str string) Scope {
	var scopes Scope
	for _, v := range strings.Split(str, " ") {
		s := strings.TrimSpace(v)
		if len(s) > 0 {
			scopes = append(scopes, s)
		}
	}
	return scopes
}
