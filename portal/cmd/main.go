package main

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

func main() {
	fmt.Println("portal!")
	logrus.SetLevel(logrus.DebugLevel)
}
