Channels
========

Hop Channels are individual units of reliable, bidirectional, ordered
communication over the transport protocol. Channels are multiplexed over the
same transport session. For more information about the motivation and function
of channels, see [LINK TODO].

TODO(dadrian)[2022-06-05]: Make sure this is up to date, move documentation into Godoc

# Basic Usage
```
package main

import (
	"log"

	"hop.computer/hop/channels"
	"hop.computer/hop/transport"
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

    // Create client and server channels. In practice,
    // many channels could be created in parallel
    // with asynchronous reads and writes.
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

# Muxers
A Muxer handles channels and interfaces betweeen individual channels and the transport session. Both the client and the server have to make a muxer from the transport session and then use the muxer to create channels. One can create channels via `muxer.CreateChannel()` and receive channel requests via
`muxer.Accept()`. `muxer.Stop()` will automatically close all channels.

#  Channels

All data is managed via `[]byte` slices. Use `channel.Write(data)` to send the data in a non-blocking fashion -- in other words, when `Write()` completes, it is not necessarily the case that that the remote peer received the connection. `channel.Read(buf)`, on the other hand, is blocking. There are two cases when `channel.Read(buf)` will finish:
- The channel has received some message: note that to read all `len(buf)` bytes, you should make use of `io.ReadFull`
- The remote peer has closed their side of the channel, namely by sending a FIN packet. In that case, there will be an EOF error returned in the `channel.Read()` call.

This behavior is consistent with `bytes.Buffer`.

Finally, `channel.Close()` is also blocking until the the channel has been torn down by both sides.

## Remaining Work
- Unreliable channels.
- Congestion control.
- `LocalAddr()`
- `RemoteAddr()`
- `SetDeadline()`
- `SetWriteDeadline()`
- `SetReadDeadline()`
