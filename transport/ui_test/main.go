package main

import (
	"fmt"

	i "github.com/tockins/interact"
)

func main() {
	i.Run(&i.Interact{
		Questions: []*i.Question{
			{
				Quest: i.Quest{
					Msg: "Would you like some coffee?",
				},
				Action: func(c i.Context) interface{} {
					val, err := c.Ans().Bool()
					if err != nil {
						return err
					}
					fmt.Println(val)
					return nil
				},
			},
		},
	})
}
