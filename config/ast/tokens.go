package ast

import (
	"bytes"
	"fmt"
	"strings"
	"text/scanner"
	"unicode"
)

// TokenType is a broad classifer of a Token
type TokenType int

// Position is the offset, row (line), and column of a Token. Offset is
// zero-indexed, row and column are 1-indexed.
type Position struct {
	Offset   int
	Row, Col int
}

// Known values of TokenType
const (
	TokenTypeKeyword TokenType = iota
	TokenTypeSetting
	TokenTypeInt
	TokenTypeFloat
	TokenTypeLBrace
	TokenTypeRBrace
	TokenTypeEnd
	TokenTypeString
	TokenTypeSentinal
)

//go:generate go run golang.org/x/tools/cmd/stringer -type TokenType .

// A Token is a TokenType and a Value. The Value may be fixed by the TokenType, or it might change.
type Token struct {
	Type  TokenType
	Value string

	Position
}

// TokenEOF is a Token with TokenTypeSentinal.
var TokenEOF = Token{Type: TokenTypeSentinal}

//go:generate go run ./gen tokens_gen.go

// IsKeyword returns the canonical keyword value for a Token if the string is a
// keyword.
func IsKeyword(s string) string {
	for _, k := range Keywords {
		if strings.EqualFold(k.Value, s) {
			return k.Value
		}
	}
	return ""
}

// IsSetting returns the canonical setting value for a Token if the string is a
// setting.
func IsSetting(s string) string {
	for _, k := range Settings {
		if strings.EqualFold(k.Value, s) {
			return k.Value
		}
	}
	return ""
}

// Tokenize takes as input a configuration and returns the set of ast in the file.
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
		if ch == '.' || ch == '-' || ch == '/' || ch == '*' || ch == ':' || ch == '_' {
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
			if tv := IsKeyword(value); tv != "" {
				tt = TokenTypeKeyword
				value = tv
			} else if tv := IsSetting(value); tv != "" {
				tt = TokenTypeSetting
				value = tv
			} else {
				tt = TokenTypeString
			}
		case '{':
			tt = TokenTypeLBrace
		case '}':
			tt = TokenTypeRBrace
		case '\n', ';':
			tt = TokenTypeEnd
			value = ";"
		default:
			panic(value)
		}
		pos := s.Pos()
		t := Token{
			Type:  tt,
			Value: value,

			Position: Position{
				Offset: pos.Offset,
				Row:    pos.Line, Col: pos.Column,
			},
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}

// Parser turns a list of Tokens into an AST.
type Parser struct {
	Raw    []byte
	Tokens []Token

	current int
	inBlock bool

	AST *Node
}

// NodeType defines which fields will be set on a Node.
type NodeType int

// Known values of NodeType
const (
	NodeTypeFile NodeType = iota
	NodeTypeSetting
	NodeTypeBlock
)

//go:generate go run golang.org/x/tools/cmd/stringer -type NodeType .

// Node represents a node in the AST for a config file. ASTs are rooted by a
// Node with NodeTypeFile. Nodes will either be a block or a setting. Settings
// with a parent set to the root node are global. Settings with a parent set to
// a block node are specific to that block.
type Node struct {
	Type   NodeType
	Parent *Node

	// Setting
	SettingKey   string
	SettingValue string

	// Block
	BlockType string
	BlockName string

	Children []*Node
}

// Walk visits all nodes in a depth-first top-down order
func (n *Node) Walk(visitor func(Node) error) error {
	if err := visitor(*n); err != nil {
		return err
	}
	for _, c := range n.Children {
		if err := c.Walk(visitor); err != nil {
			return err
		}
	}
	return nil
}

// NewParser returns an initialized Parser with a root AST.
func NewParser(raw []byte, tokens []Token) Parser {
	return Parser{
		Raw:    raw,
		Tokens: tokens,
		AST: &Node{
			Type: NodeTypeFile,
		},
	}
}

// PeekToken returns the next token without advancing the cursor. If there is no
// next Token, this returns Control.EOF.
func (p Parser) PeekToken() Token {
	if len(p.Tokens) > p.current {
		return p.Tokens[p.current]
	}
	return TokenEOF
}

// ConsumeToken returns the next Token and advances the cursor. If there is no
// next Token, this returns Control.EOF.
func (p *Parser) ConsumeToken() Token {
	out := p.PeekToken()
	p.current++
	return out
}

// Rollback moves the cursor back one token.
func (p *Parser) Rollback() {
	p.current--
}

// ConsumeTokenOfType consumes the next Token. If the next Token does not have
// the expected TokenType, this returns an error. The Token is always consumed.
func (p *Parser) ConsumeTokenOfType(tt TokenType) (Token, error) {
	t := p.ConsumeToken()
	if t.Type != tt {
		return TokenEOF, fmt.Errorf("unexpected Token: wanted %q, got %q", tt, t.Type)
	}
	return t, nil
}

// Parse runs the parser on the Tokens to populate the AST.
func (p *Parser) Parse() error {
	p.inBlock = false
	children, err := p.ParseBlock(p.AST)
	if err != nil {
		return err
	}
	p.AST.Children = children
	return nil
}

// ParseNode parses a single Node at the current token. If the token cannot being a node or the expected Tokens are not found, this errors.
func (p *Parser) ParseNode(parent *Node) (*Node, error) {
	for {
		t := p.PeekToken()
		switch t.Type {
		case TokenTypeSetting:
			return p.parseSetting(parent)
		case TokenTypeKeyword:
			return p.ParseKeyword(parent)
		default:
			return nil, fmt.Errorf("unimplemented %s: %s", t.Type, t.Value)
		}
	}
}

// ParseBlock parses a block of Nodes. If the current Token cannot begin a
// block, this errors. Blocks cannot be nested, and block state is tracked on
// the parser.
func (p *Parser) ParseBlock(parent *Node) (statements []*Node, err error) {
	for {
		t := p.ConsumeToken()
		if t.Type == TokenTypeEnd {
			continue
		}
		if p.inBlock {
			switch t.Type {
			case TokenTypeRBrace:
				p.inBlock = false
				return
			case TokenTypeSentinal:
				err = fmt.Errorf("file ended before %q block ended", parent.BlockType)
				return
			}
		}
		if !p.inBlock && t.Type == TokenTypeSentinal {
			return
		}
		p.Rollback()
		var n *Node
		n, err = p.ParseNode(parent)
		if err != nil {
			return
		}
		statements = append(statements, n)
	}
}

// ParseSetting parses [Setting String End] into a Node.
func (p *Parser) parseSetting(parent *Node) (*Node, error) {
	ts := p.ConsumeToken()
	if ts.Type != TokenTypeSetting {
		return nil, fmt.Errorf("expected TokenTypeSetting, got %s", ts.Type)
	}
	tv, err := p.ConsumeTokenOfType(TokenTypeString)
	if err != nil {
		return nil, fmt.Errorf("a setting must be followed by a string value: %w", err)
	}
	_, err = p.ConsumeTokenOfType(TokenTypeEnd)
	if err != nil {
		return nil, fmt.Errorf("setting did not end with token %s", TokenTypeEnd)
	}
	n := &Node{
		Type:         NodeTypeSetting,
		Parent:       parent,
		SettingKey:   ts.Value,
		SettingValue: tv.Value,
	}
	return n, nil
}

// ParseKeyword parses all Keywords. Certain keywords may involve parsing a block.
func (p *Parser) ParseKeyword(parent *Node) (*Node, error) {
	tk := p.ConsumeToken()
	if tk.Type != TokenTypeKeyword {
		return nil, fmt.Errorf("expected TokenTypeKeyword, got %s", tk.Type)
	}
	switch tk.Value {
	case Keyword.Host.Value:
		if p.inBlock {
			return nil, fmt.Errorf("cannot define a Host in a block")
		}
		s, err := p.ConsumeTokenOfType(TokenTypeString)
		if err != nil {
			return nil, fmt.Errorf("%q must be followed by a host pattern: %w", tk.Value, err)
		}
		_, err = p.ConsumeTokenOfType(TokenTypeLBrace)
		if err != nil {
			return nil, fmt.Errorf("%q pattern was not followed by a lbrace: %w", Keyword.Host, err)
		}
		n := &Node{
			Type:      NodeTypeBlock,
			Parent:    parent,
			BlockType: "Host",
			BlockName: s.Value,
		}
		p.inBlock = true
		children, err := p.ParseBlock(n)
		if err != nil {
			return nil, err
		}
		n.Children = children
		return n, nil
	case Keyword.Include.Value:
		s, err := p.ConsumeTokenOfType(TokenTypeString)
		if err != nil {
			return nil, fmt.Errorf("%q must be followed by a host pattern: %w", tk.Value, err)
		}
		return &Node{
			Type:      NodeTypeBlock,
			Parent:    parent,
			BlockType: "Include",
			BlockName: s.Value,
		}, nil
	default:
		return nil, fmt.Errorf("unimplemented Keyword %q", tk.Value)
	}
}
