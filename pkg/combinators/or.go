// Package combinators defines combinator functions such as Or. Once Go 1.18
// lands, this package will be much easier to implement, since each function
// won't have to be as type-specific.
package combinators

// StringOr returns s if it is non-empty. Otherwise, it returns the provided
// default.
func StringOr(s, orDefault string) string {
	if s == "" {
		return orDefault
	}
	return s
}
