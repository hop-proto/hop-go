// Code generated DO NOT EDIT.
package tokens

// Keyword contains definitions for all Tokens with TokenTypeKeyword. They can
// be safely compared by value.
var Keyword = struct {
	Address      Token
	AutoSelfSign Token
	CAFile       Token
	Certificate  Token
	Host         Token
	Include      Token
	Key          Token
	Number       Token
	Port         Token
	Word         Token
}{
	Address: Token{
		Type:  TokenTypeKeyword,
		Value: "Address",
	},
	AutoSelfSign: Token{
		Type:  TokenTypeKeyword,
		Value: "AutoSelfSign",
	},
	CAFile: Token{
		Type:  TokenTypeKeyword,
		Value: "CAFile",
	},
	Certificate: Token{
		Type:  TokenTypeKeyword,
		Value: "Certificate",
	},
	Host: Token{
		Type:  TokenTypeKeyword,
		Value: "Host",
	},
	Include: Token{
		Type:  TokenTypeKeyword,
		Value: "Include",
	},
	Key: Token{
		Type:  TokenTypeKeyword,
		Value: "Key",
	},
	Number: Token{
		Type:  TokenTypeKeyword,
		Value: "Number",
	},
	Port: Token{
		Type:  TokenTypeKeyword,
		Value: "Port",
	},
	Word: Token{
		Type:  TokenTypeKeyword,
		Value: "Word",
	},
}

// Keywords is an array containing all values from Keyword.
var Keywords = []Token{
	Keyword.Address,
	Keyword.AutoSelfSign,
	Keyword.CAFile,
	Keyword.Certificate,
	Keyword.Host,
	Keyword.Include,
	Keyword.Key,
	Keyword.Number,
	Keyword.Port,
	Keyword.Word,
}
