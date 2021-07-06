TODO: Authorization Grant Channel Spec

ipcserver.go: POC implementation of portion of hop server daemon that interacts with hop client. 
    Checks that the client is a descendent of the "daemon" process.

authgrants.go: basic outline of how to deal with various auth grant message types

simpleecho: super simple UDS server (use nc -U echo.sock to interact with it)

client: contains a client program that acts like a hop client that interacts with the hop server daemon

Milestones:
- Proper Intent Message encapsulation and decapsulation
- Network Proxy Channels
- Running custom commands (interactive shell)
- Organize code into appropriate modules
- Server can support multiple connections
- Using keys for identity + actually adding authgrants
- Enforcing time restrictions on authgrants

