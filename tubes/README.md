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



# Congestion Control

Reliable Tubes use a simple congestion control algorithm to ensure the reliable delivery of packets while accounting for network loss and delay.

**Window Size**: The window size is fixed at 128 and remains constant throughout the file transfer. This size was arbitrarily chosen based on testing and has demonstrated good performance in both usability and file transfer. The window advances synchronously on both the sender and receiver sides as packets are received and acknowledged. Any packets received outside the window are ignored and dropped.

**Acknowledgment**: To limit network congestion, Reliable Tubes use cumulative acknowledgments (ACKs). This means that every frame below the ACK number is considered successfully received. This approach reduces the number of ACKs sent, improving efficiency in high-latency and congestive environments.



**Retransmission**: Reliable Tubes employ two primary retransmission mechanisms to ensure reliability:

**1 - RTR Flag**: If the receiver detects that a frame has been skipped—meaning it receives frame (n+1) before frame (n)—it considers frame (n) lost. To request retransmission, the receiver:

1. Sends an ACK for the last correctly received frame (e.g., if frames 1 and 5 arrive, it acknowledges frame 1).
2. Sets the RTR (Retransmission Request) flag to `true` and includes the number of missing frames in the data length field (e.g., here 3).
3. Requests retransmission for the missing frames (e.g., frames 2, 3, and 4).

However, this mechanism alone does not distinguish between true packet loss and simple out-of-order delivery. To prevent unnecessary retransmissions:

- The receiver introduces a wait time before requesting retransmission.
- If the missing frame arrives within this wait period, the retransmission request is canceled.
- The wait time is calculated as:

`Wait Time = Estimated RTT - Frame Queue Time`

This prevents unnecessary retransmissions due to network jitter.


**2 - Retransmission Timeout (RTO)**: If a retransmitted frame is also lost, Reliable Tubes use a Retransmission Timeout (RTO) mechanism** to ensure delivery.

- After the first retransmission attempt, the sender waits for 1 RTT.
- If no ACK is received within that waiting period the sender will send an RTO frame.
- The RTO event occurs at most 2 RTTs after the initial frame transmission.
- When a RTO event is occurring, the receiver will send a RTR ACK with a length ranging from 0 to n, the number of missing frames, describing the state of the receiver causing this congestive event.


## Remaining Work
- Unreliable channels.
- `LocalAddr()`
- `RemoteAddr()`
- `SetDeadline()`
- `SetWriteDeadline()`
- `SetReadDeadline()`
