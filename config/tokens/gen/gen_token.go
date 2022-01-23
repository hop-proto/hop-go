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
package tokens

// Keyword contains definitions for all Tokens with TokenTypeKeyword. They can
// be safely compared by value.
var Keyword = struct {
	{{ range .Keywords}}
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

// Keywords is an array containing all values from Keyword.
var Keywords = []Token{
{{- range .Keywords }}
	Keyword.{{ .Name }},
{{- end }}
}
`

type keyword struct {
	Name string
}

type tokenCtx struct {
	Keywords []keyword
}

type keywordSlice []keyword

var _ sort.Interface = keywordSlice{}

func (k keywordSlice) Len() int {
	return len(k)
}

func (k keywordSlice) Less(i, j int) bool {
	return strings.Compare(k[i].Name, k[j].Name) < 0
}

func (k keywordSlice) Swap(i, j int) {
	tmp := k[i]
	k[i] = k[j]
	k[j] = tmp
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
	keywords := []keyword{
		{Name: "Include"},
		{Name: "CAFile"},
		{Name: "Host"},
		{Name: "Key"},
		{Name: "Certificate"},
		{Name: "AutoSelfSign"},
		{Name: "Address"},
		{Name: "Port"},
		{Name: "Number"},
		{Name: "Word"},
	}
	sort.Sort(keywordSlice(keywords))

	t := template.New("tokens")
	_, err := t.Parse(tmpl)
	if err != nil {
		logrus.Fatalf("unable to parse template: %s", err)
	}
	buf := bytes.Buffer{}
	err = t.Execute(&buf, tokenCtx{Keywords: keywords})
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
