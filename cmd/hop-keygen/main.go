package main

import (
	"flag"
	"os"

	"zmap.io/portal/app"
)

func main() { //add a key
	var fs flag.FlagSet

	suffix := "/.hop/key"
	fs.StringVar(&suffix, "s", suffix, "path suffix homedir + suffix")

	var addToAuthKeys bool
	fs.BoolVar(&addToAuthKeys, "a", false, "add the key to its own authorized keys file")

	fs.Parse(os.Args[1:])
	app.KeyGen(suffix, addToAuthKeys)
}
