package main

import (
	"bytes"
	"go/format"
	"io"
	"os"
	"text/template"

	"github.com/sirupsen/logrus"
)

var tmpl = `// Code generated DO NOT EDIT.
package config

{{ range .Tokens }}
var {{ .Variable }} = Token{ Value: {{printf "%q" .Value}}, Flags: {{ printf "%s" .Flags }} }
{{- end }}
var TOKENS = []Token{
{{- range .Tokens }}
	{{ .Variable }},
{{- end }}
}
`

type tokenDefinition struct {
	Variable string
	Value    string
	Flags    string
}

type tokenCtx struct {
	Tokens []tokenDefinition
}

func main() {
	var f io.Writer
	if len(os.Args) < 2 {
		f = os.Stdout
	} else {
		fd, err := os.Create(os.Args[1])
		if err != nil {
			logrus.Fatalf("unable to create %q: %s", os.Args[1], fd)
		}
		f = fd
	}
	tokens := []tokenDefinition{
		{Variable: "INCLUDE", Value: "Include", Flags: "TokenFlagCaseInsensitive"},
		{Variable: "CAFILE", Value: "CAFile", Flags: "TokenFlagCaseInsensitive"},
		{Variable: "HOST", Value: "Host", Flags: "TokenFlagCaseInsensitive"},
	}
	t := template.New("tokens")
	_, err := t.Parse(tmpl)
	if err != nil {
		logrus.Fatalf("unable to parse template: %s", err)
	}
	buf := bytes.Buffer{}
	err = t.Execute(&buf, tokenCtx{Tokens: tokens})
	if err != nil {
		logrus.Fatalf("unable to execute template: %s", err)
	}
	out, err := format.Source(buf.Bytes())
	if err != nil {
		logrus.Fatalf("unable to format source: %s", err)
	}
	f.Write(out)
}
