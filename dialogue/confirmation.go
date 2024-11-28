// Package dialogue contains utilities of getting user input
package dialogue

import (
	"fmt"
	"golang.org/x/term"
	"syscall"
)

// TODO this work but is very not a good solution
func AskForConfirmation() bool {
	fmt.Println("Press 'y' to confirm or 'n' to cancel:")

	oldState, err := term.MakeRaw(int(syscall.Stdin))
	if err != nil {
		fmt.Println("Error setting raw mode:", err)
		return false
	}
	defer term.Restore(int(syscall.Stdin), oldState)

	var input []byte = make([]byte, 1)
	syscall.Read(syscall.Stdin, input)

	if input[0] == 13 {
		return true
	}

	return false
}
