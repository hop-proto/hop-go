package tokens

import (
	"bytes"
	"strings"
	"text/scanner"
	"unicode"
)

// TokenType is a broad classifer of a Token
type TokenType int

// Known values of TokenType
const (
	TokenTypeKeyword TokenType = iota
	TokenTypeInt
	TokenTypeFloat
	TokenTypeScope
	TokenTypeEnd
	TokenTypeString
)

//go:generate go run golang.org/x/tools/cmd/stringer -type TokenType .

// A Token is a TokenType and a Value. The Value may be fixed by the TokenType, or it might change.
type Token struct {
	Type  TokenType
	Value string
}

//go:generate go run ./gen tokens_gen.go

// Tokenize takes as input a configuration and returns the set of tokens in the file.
func Tokenize(b []byte) ([]Token, error) {
	var tokens []Token
	buf := bytes.NewBuffer(b)
	s := scanner.Scanner{}
	s.Init(buf)
	s.Whitespace = (1 << ' ') | (1 << '\t') | (1 << '\r')
	s.Mode = scanner.ScanIdents | scanner.SkipComments
	s.IsIdentRune = func(ch rune, i int) bool {
		if unicode.IsLetter(ch) {
			return true
		}
		if unicode.IsDigit(ch) {
			return true
		}
		if ch == '.' || ch == '-' || ch == '/' || ch == '*' {
			return true
		}
		return false
	}
	for r := s.Scan(); r != scanner.EOF; r = s.Scan() {
		value := s.TokenText()
		var tt TokenType
		switch r {
		case scanner.Int:
			tt = TokenTypeInt
		case scanner.Float:
			tt = TokenTypeInt
		case scanner.Ident:
			found := false
			for _, k := range Keywords {
				if strings.EqualFold(k.Value, value) {
					tt = TokenTypeKeyword
					found = true
					break
				}
			}
			if !found {
				tt = TokenTypeString
			}
		case '{', '}':
			tt = TokenTypeScope
		case '\n', ';':
			tt = TokenTypeEnd
			value = ";"
		default:
			panic(value)
		}
		tokens = append(tokens, Token{Type: tt, Value: value})
	}
	return tokens, nil
}
