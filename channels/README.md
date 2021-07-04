Channels
========

Hop Channels are individual units of reliable, bidirectional, ordered communication over the transport protocol.
Channels are multiplexed over the same transport session.
For more information about the motivation and function of channels, see [LINK TODO].

# Architecture
A Muxer handles channels and interfaces betweeen individual channels and the transport session. Both the client and the server have to make a muxer from the transport session and then use the muxer to create channels.

## Basic Usage
```
package main

import (
    "log"

	"zmap.io/portal/channels"
    "zmap.io/portal/transport"
)

func main() {
    logger := log.New(os.Stdout, "", 0)


    // Create transport server and client connections.
    // In practice, each side of the muxer/channel connection
    // would be running in a separate process.
    transportServer, _ := createTransportServer()
    go server.Serve()
    serverConn, _ := server.AcceptTimeout(time.Minute)
    clientConn, _ := createTransportClient()

    // Create client and server muxers
    muxerServer := channels.NewMuxer(serverConn, serverConn)
	go muxerServer.Start()
	defer muxerServer.Stop()
    muxerClient := NewMuxer(clientConn, clientConn)
	go muxerClient.Start()
    defer muxerClient.Stop()

    // Create client and server channels.
    clientChan, _ := muxerClient.CreateChannel(/* TODO */)
	serverChan, _ := muxerServer.Accept()
    
    // Client and server writes.
	clientData := []byte("some data from client")
    serverData := []byte("some data from server")
    clientChan.Write(clientData)
    serverChan.Write(serverData)

    serverReadData := make([]byte, len(clientData))
    serverChan.Read(serverReadData)
    logger.Println(serverReadData) // "some data from client"

    // The channel Close() call blocks, so we need to execute this in a separate thread.
    go func () {
        clientChan.Close()
        clientReadData := make([]byte, len(serverData))
        clientChan.Read(clientReadData)
        logger.Println(clientReadData) // "some data from server"
    }()
	serverChan.Close()
}
```

