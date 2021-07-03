package main

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/channels"
	"zmap.io/portal/transport"
)

func startClient() {
	transportConn, err := transport.Dial("udp", "127.0.0.1:8888", nil)
	if err != nil {
		logrus.Fatalf("error dialing server: %v", err)
	}
	err = transportConn.Handshake()
	if err != nil {
		logrus.Fatalf("issue with handshake: %v", err)
	}

	mc := channels.NewMuxer(transportConn, transportConn)
	go mc.Start()
	defer mc.Stop()

	channel, err := mc.CreateChannel(1 << 8)
	if err != nil {
		logrus.Fatalf("error making channel: %v", err)
	}

	testData := "hi i am some data"

	_, err = channel.Write([]byte(testData))
	if err != nil {
		logrus.Fatalf("error writing to channel: %v", err)
	}
	println("Successfully wrote my data")

	err = channel.Close()
	if err != nil {
		fmt.Printf("error closing channel: %v", err)
	}

	//infinite loop so the client program doesn't quit
	//otherwise client quits before server can read data
	//TODO: Figure out how to check if the other side closed channel

	for {
	}

}

//First try below: messy and doesn't really work
//const server1 = "/tmp/server1.sock"

// func read(r net.Conn, finished chan bool, intent string) {
// 	defer func() {
// 		finished <- true
// 	}()
// 	log.Printf("Connected to server [%s]", r.RemoteAddr().Network())

// 	reader := bufio.NewReader(os.Stdin)
// 	b := bufio.NewWriter(r)
// 	recv := bufio.NewReader(r)
// 	out := bufio.NewWriter(os.Stdout)
// 	//send intent
// 	b.Write([]byte(intent))

// 	for {
// 		resp, err := recv.ReadBytes('\n')
// 		if err != nil {
// 			break
// 		}
// 		out.Write(resp)
// 		line, err := reader.ReadBytes('\n')
// 		if err != nil {
// 			break
// 		}
// 		b.Write(line)
// 		fmt.Printf("sent: %v", line)

// 	}
// 	// buf := make([]byte, 1024)
// 	// n, err := r.Read(buf[:])
// 	// if err != nil {
// 	// 	return
// 	// }
// 	// println("Client got:", string(buf[0:n]))
// }

// func startClient() {
// 	//wait for user input
// 	//parse user cmd to connect to hop server
// 	//rewire server output so the shell becomes the server.

// 	reader := bufio.NewReader(os.Stdin)
// 	for {
// 		fmt.Print("user@localhost: ")
// 		text, _ := reader.ReadString('\n')
// 		args := strings.Split(strings.TrimSpace(text), " ")
// 		if len(args) == 2 {
// 			if args[0] == "hop" && args[1] == "server1" {
// 				fmt.Println("Connecting to server1...")
// 				break
// 			}
// 		}
// 		fmt.Println("unrecognized command")
// 	}

// 	//connect to server1 (in reality this would be over a network connection using hop protocol)
// 	//implemented using UDS for demo purposes
// 	c, err := net.Dial("unix", server1)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer c.Close()

// 	finished := make(chan bool)
// 	go read(c, finished, "user@server1, action, server2\n")

// 	<-finished
// }
