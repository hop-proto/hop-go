package main

import (
	"flag"
	"os"

	"zmap.io/portal/app"
)

func main() { //add a key
	var fs flag.FlagSet

	dir := "/.hop"
	fs.StringVar(&dir, "d", dir, "homedir + dir is dir where key stored")

	filename := "key"
	fs.StringVar(&filename, "f", filename, "name of key")

	var addToAuthKeys bool
	fs.BoolVar(&addToAuthKeys, "a", false, "add the key to its own authorized keys file")

	fs.Parse(os.Args[1:])
	app.KeyGen(dir, filename, addToAuthKeys)
}
