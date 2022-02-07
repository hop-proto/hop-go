// Code generated DO NOT EDIT.
package tokens

// Keyword contains definitions for all Tokens with TokenTypeKeyword. They can
// be safely compared by value.
var Keyword = struct {
	Host    Token
	Include Token
}{
	Host: Token{
		Type:  TokenTypeKeyword,
		Value: "Host",
	},
	Include: Token{
		Type:  TokenTypeKeyword,
		Value: "Include",
	},
}

// Keywords is an array containing all values from Setting
var Keywords = []Token{
	Keyword.Host,
	Keyword.Include,
}

// Setting contains definitions for all Tokens with TokenTypeKeyword. They can
// be safely compared by value.
var Setting = struct {
	Address      Token
	AutoSelfSign Token
	CAFile       Token
	Certificate  Token
	Key          Token
	Number       Token
	Port         Token
	Word         Token
}{
	Address: Token{
		Type:  TokenTypeSetting,
		Value: "Address",
	},
	AutoSelfSign: Token{
		Type:  TokenTypeSetting,
		Value: "AutoSelfSign",
	},
	CAFile: Token{
		Type:  TokenTypeSetting,
		Value: "CAFile",
	},
	Certificate: Token{
		Type:  TokenTypeSetting,
		Value: "Certificate",
	},
	Key: Token{
		Type:  TokenTypeSetting,
		Value: "Key",
	},
	Number: Token{
		Type:  TokenTypeSetting,
		Value: "Number",
	},
	Port: Token{
		Type:  TokenTypeSetting,
		Value: "Port",
	},
	Word: Token{
		Type:  TokenTypeSetting,
		Value: "Word",
	},
}

// Settings is an array containing all values from Setting
var Settings = []Token{
	Setting.Address,
	Setting.AutoSelfSign,
	Setting.CAFile,
	Setting.Certificate,
	Setting.Key,
	Setting.Number,
	Setting.Port,
	Setting.Word,
}
