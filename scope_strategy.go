package oauth2

type ScopeStrategy func(scopes Scope, needle ...string) bool

// DefaultScopeStrategy does a 1 == 1 comparison
func DefaultScopeStrategy(scopes Scope, needle ...string) bool {
	comp := func(needle string) bool {
		for _, scope := range scopes {
			if scope == needle {
				return true
			}
		}
		return false
	}

	for _, want := range needle {
		if want != "" && false == comp(want) {
			return false
		}
	}
	return true
}

// HirarchicalScopeStrategy does a partial match  foo == foo.bar
func HirarchicalScopeStrategy(scopes Scope, needle ...string) bool {
	comp := func(needle string) bool {
		for _, scope := range scopes {
			scopeLen := len(scope)
			needleLen := len(needle)

			//exact match
			// true : abc.def == abc.def
			// false: abc.def == foo.bar
			// false: xyz == foo.bar
			if (needleLen == scopeLen && scope == needle) {
				return true
			}

			//partial match match
			// true : abc == abc.def
			// false: abc.def == abc
			if (needleLen > scopeLen && scope == needle[:scopeLen] && needle[scopeLen] == '.') {
				return true
			}
		}
		return false
	}

	for _, want := range needle {
		if want != "" && false == comp(want) {
			return false
		}
	}
	return true
}
