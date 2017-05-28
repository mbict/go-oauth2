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

func HirarchicalScopeStrategy(scopes Scope, needle ...string) bool {
	return false
}
