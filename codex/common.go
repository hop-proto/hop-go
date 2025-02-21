// Package codex provides functions specific to code execution tubes
package codex

import "io"

type Codex interface {
	Resume()
	Redirect() *io.PipeReader
	Restore()
	Raw()
}
