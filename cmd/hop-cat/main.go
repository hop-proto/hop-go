package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/certs"
)

var outform string
var inform string
var inType string

var jsonOut bool

func outputCertificatePEM(c *certs.Certificate, w io.Writer) error {
	b, err := certs.EncodeCertificateToPEM(c)
	if err != nil {
		return err
	}
	w.Write(b)
	w.Write([]byte("\n"))
	return nil
}

func outputCertificateBIN(c *certs.Certificate, w io.Writer) error {
	_, err := c.WriteTo(w)
	return err
}

type certificateOutputFunction func(*certs.Certificate, io.Writer) error

func certOutputFormatMuxer(format string) (certificateOutputFunction, error) {
	switch format {
	case "pem":
		return outputCertificatePEM, nil
	case "bin":
		return outputCertificateBIN, nil
	default:
		return nil, fmt.Errorf("unknown output format %q", format)
	}
}

// TODO(dadrian): Handle multiple concatenated certs
func inputCertificatePEM(r io.Reader) ([]*certs.Certificate, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	c, err := certs.ReadCertificatePEM(b)
	if err != nil {
		return nil, err
	}
	return []*certs.Certificate{c}, nil
}

func inputCertificateBIN(r io.Reader) ([]*certs.Certificate, error) {
	out := make([]*certs.Certificate, 0, 1)
	for {
		c := new(certs.Certificate)
		_, err := c.ReadFrom(r)
		if err == io.EOF {
			return out, nil
		}
		out = append(out, c)
	}
}

type certificateInputFunction func(io.Reader) ([]*certs.Certificate, error)

func certInputFormatMuxer(format string) (certificateInputFunction, error) {
	switch format {
	case "pem":
		return inputCertificatePEM, nil
	case "bin":
		return inputCertificateBIN, nil
	default:
		return nil, fmt.Errorf("unknown input format %q", format)
	}
}

func main() {
	flag.StringVar(&inform, "inform", "pem", "input format (pem or bin)")
	flag.StringVar(&outform, "outform", "pem", "output format (pem or bin)")
	flag.BoolVar(&jsonOut, "json", false, "Output JSON representation before output")
	flag.StringVar(&inType, "type", "auto", "auto")
	flag.Parse()

	inform = strings.ToLower(inform)
	outform = strings.ToLower(outform)

	if inType != "auto" {
		logrus.Fatal("only auto intype supported")
	}

	inFunc, err := certInputFormatMuxer(inform)
	if err != nil {
		logrus.Fatalf("error setting input format: %q", inform)
	}
	certs, err := inFunc(os.Stdin)
	if err != nil {
		logrus.Fatalf("error reading certs: %s", err)
	}

	outFunc, err := certOutputFormatMuxer(outform)
	if err != nil {
		logrus.Fatalf("error setting output format: %q", outform)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, c := range certs {
		if jsonOut {
			enc.Encode(c)
		}
		err := outFunc(c, os.Stdout)
		if err != nil {
			logrus.Fatalf("error writing output: %s", err)
		}
	}
}
