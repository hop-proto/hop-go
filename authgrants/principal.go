package authgrants

import (
	"bufio"
	"fmt"
	"io"
)

var hostToIPAddr = map[string]string{ //TODO(baumanl): this should be dealt with in some user hop config file
	"scratch-01": "10.216.2.64",
	"scratch-02": "10.216.2.128",
	"scratch-07": "10.216.2.208",
	"localhost":  "127.0.0.1",
}

//Display prints the authgrant approval prompt to terminal and continues prompting until user enters "y" or "n"
func (r *Intent) Prompt(reader *io.PipeReader) bool {
	var ans string
	for ans != "y" && ans != "n" {
		if r.tubeType == commandTube {
			fmt.Printf("\nAllow %v@%v to run %v on %v@%v? [y/n]: ",
				r.clientUsername,
				r.clientSNI,
				r.action,
				r.serverUsername,
				r.serverSNI)
		} else {
			fmt.Printf("\nAllow %v@%v to open a default shell as %v@%v? [y/n]: ",
				r.clientUsername,
				r.clientSNI,
				r.serverUsername,
				r.serverSNI,
			)
		}
		scanner := bufio.NewScanner(reader)
		scanner.Scan()
		ans = scanner.Text()
	}
	return ans == "y"
}
