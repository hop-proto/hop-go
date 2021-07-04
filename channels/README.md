Channels
========

Hop Channels are individual units of reliable, bidirectional, ordered communication over the transport protocol.
Channels are multiplexed over the same transport session.
For more information about the motivation and function of channels, see [LINK TODO].

# Architecture
A Muxer handles channels and interfaces betweeen individual channels and the transport session. Both the client and the server have to make a muxer from the transport session and then use the muxer to create channels.

## Basic Usage
```

```

