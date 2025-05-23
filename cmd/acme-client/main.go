package main

import (
	"hop.computer/hop/certs"
	"os"
)

func main() {
	cert := certs.Certificate{}
	cert.IDChunk = certs.IDChunk{
		Blocks: []certs.Name{
			certs.DNSName("requester.com"),
		},
	}
	buf, _ := cert.Marshal()
	os.Stdout.Write(buf)
}
