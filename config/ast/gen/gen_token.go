package main

import (
	"bytes"
	"go/format"
	"io"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/sirupsen/logrus"
)

var tmpl = `// Code generated DO NOT EDIT.
package ast

// Keyword contains definitions for all Tokens with TokenTypeKeyword. They can
// be safely compared by value.
var Keyword = struct {
	{{ range .Keywords }}
	{{ .Name }} Token
	{{- end }}
}{
	{{- range .Keywords }}
	{{ .Name }}: Token{
		Type: TokenTypeKeyword,
		Value: {{ printf "%q" .Name }},
	},
	{{- end }}
}

// Keywords is an array containing all values from Setting
var Keywords = []Token{
{{- range .Keywords }}
	Keyword.{{ .Name }},
{{- end }}
}

// Setting contains definitions for all Tokens with TokenTypeKeyword. They can
// be safely compared by value.
var Setting = struct {
	{{ range .Settings}}
	{{ .Name }} Token
	{{- end }}
}{
	{{- range .Settings }}
	{{ .Name }}: Token{
		Type: TokenTypeSetting,
		Value: {{ printf "%q" .Name }},
	},
	{{- end }}
}

// Settings is an array containing all values from Setting
var Settings = []Token{
{{- range .Settings }}
	Setting.{{ .Name }},
{{- end }}
}
`

type typeDefinition struct {
	Name string
}

type tokenCtx struct {
	Keywords []typeDefinition
	Settings []typeDefinition
}

type typeSlice []typeDefinition

var _ sort.Interface = typeSlice{}

func (s typeSlice) Len() int {
	return len(s)
}

func (s typeSlice) Less(i, j int) bool {
	return strings.Compare(s[i].Name, s[j].Name) < 0
}

func (s typeSlice) Swap(i, j int) {
	tmp := s[i]
	s[i] = s[j]
	s[j] = tmp
}

func main() {
	var f io.Writer
	if len(os.Args) < 2 {
		f = os.Stdout
	} else {
		fd, err := os.Create(os.Args[1])
		if err != nil {
			logrus.Fatalf("unable to create %q: %s", os.Args[1], err)
		}
		f = fd
	}
	settings := []typeDefinition{
		{Name: "CAFile"},
		{Name: "Key"},
		{Name: "Certificate"},
		{Name: "AutoSelfSign"},
		{Name: "Address"},
		{Name: "Port"},
		{Name: "Number"},
		{Name: "Word"},
		{Name: "ListenAddress"},
	}
	sort.Sort(typeSlice(settings))

	keywords := []typeDefinition{
		{Name: "Host"},
		{Name: "Include"},
		{Name: "Server"},
	}
	sort.Sort(typeSlice(keywords))

	data := tokenCtx{
		Keywords: keywords,
		Settings: settings,
	}

	t := template.New("ast")
	_, err := t.Parse(tmpl)
	if err != nil {
		logrus.Fatalf("unable to parse template: %s", err)
	}
	buf := bytes.Buffer{}
	err = t.Execute(&buf, data)
	if err != nil {
		logrus.Fatalf("unable to execute template: %s", err)
	}
	out, err := format.Source(buf.Bytes())
	//out := buf.Bytes()
	if err != nil {
		logrus.Fatalf("unable to format source: %s", err)
	}
	f.Write(out)
}
