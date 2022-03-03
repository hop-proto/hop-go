// Package glob matches shell-style globs against input.
package glob

type glob struct {
	pattern string
	// cmp     func(string, string) bool
}

// An Option modifies the behavior of a call to Glob.
type Option func(*glob)

// CaseSensitive requires the input to match case to the pattern
// var CaseSensitive Option = func(g *glob) {
// 	g.cmp = func(a, b string) bool {
// 		return a == b
// 	}
// }

// Glob matches input against pattern. It returns true if there is a match.
// Options change comparison behavior.
func Glob(pattern, input string, opts ...Option) bool {
	g := glob{
		pattern: pattern,
		// cmp:     strings.EqualFold,
	}
	for _, o := range opts {
		o(&g)
	}
	i := 0
	j := 0
	asterisk := false
	for i < len(pattern) {
		if pattern[i] == '*' {
			asterisk = true
			i++
		} else {
			match := pattern[i] == input[j]
			if !asterisk && !match {
				return false
			}
			if match {
				i++
			}
			if asterisk && match {
				asterisk = false
			}
			j++
		}
		if j >= len(input) {
			break
		}
	}
	return i == len(pattern) && (asterisk || j == len(input))
}
