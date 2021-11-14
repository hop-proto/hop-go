package certs

import "bytes"

type Pool struct {
	total int

	// TODO(dadrian): Should this be as an argument?
	buf bytes.Buffer
}
