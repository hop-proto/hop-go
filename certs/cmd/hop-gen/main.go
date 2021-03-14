package main

import (
	"os"

	"zmap.io/portal/certs"
)

func main() {
	c := certs.Certificate{}
	c.WriteTo(os.Stdout)
}
