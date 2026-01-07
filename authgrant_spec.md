## Secure Identity Forwarding (Authorization Grant Protocol)


Hop seeks to provide native support for secure identity forwarding that abides by the Secure Delegation Principal outlined by Kogan et al. In contrast to ssh-agent identity forwarding, Hop seeks to avoid exposing agents to unauthenticated key challenges and to provide fine-grained control over how the Principal identity is used by semi-trusted Delegates.

**Secure Delegation Principle**: The Delegate is only able to act under the Principal's authority after the Principal can verify and enforce the Delegate's intent. The intent consists of 4 components (will be discussed in much greater detail below):
1. **Who** (the Delegate)
2. **What** (the action)
3. **To Whom** (the target)
4. **When** (deadline/expiration date)

On inception a Hop client process determines whether it is acting as a Principal or Delegate. The default behavior is for the hop client to be a Principal, but this can be overridden via the client config file or command line arguments.

**Principal** Client:
- must have proof of identity (e.g. cert + static private key)
- handles requests for authorization grants from Delegates

**Delegate** Client:
- must request an authorization grant from a Principal Client
- must have proof of identity (e.g. \[self-signed\]cert + static private key)
- to request an auth grant: hopd must still have an active hop session with a Principal hop client (once an auth grant has been issued the hop session with the Principal can terminate, but no further auth grants can be granted and further identity chaining will not be possible.)

## Authgrant Flow

```sequence
PClient-->ServerA: Principal connects to ServerA
PClient-->ServerA: Principal spawns delegate client (DClient) on ServerA
DClient--ServerA-->PClient: Intent Request
Authorize Intent
PClient--ServerA-->ServerB: Intent Communication
ServerB--ServerA--PClient--ServerA-->DClient: Intent Confirmation
PClient-->ServerB: Delegate connects to ServerB
```
I made a rudimentary animation of this process in google slides (present and click through animations). The demo is [here](https://docs.google.com/presentation/d/1ko2Q3L3h53x7km9UPEJ0RhSkpTbN8zR1naasRe5R1kE/edit#slide=id.g16983377a29_0_217).

### Principal Client Connects to ServerA
- Principal client performs a standard hop handshake with ServerA and starts a hop session
- Within this hop session the user starts a Delegate Hop Client on Server A.
- hopd adds an entry to a map of PID --> hop session with Principal
- hopd listens on an abstract unix domain socket for requests from descendant processes to contact their respective Principal.

### Intent Request

- The Delegate client (DClient) uses IPC to contact the hopd server (ServerA) and request to send an Intent Request to its Principal (PClient).
- ServerA verifies that DClient is a descendant process and uses its PID to locate the hop session it has with its Principal. This is simply the most convenient way for ServerA to know which Principal to send the request to. The security of authgrants does *not* depend on DClient being a descendant of ServerA.
- ServerA opens an authorization grant tube (AGT) with PClient and sends the Intent Request message (outlined below).

### Intent Request Fields

| Field           | Size         |
| -----------     |--------------|
| Grant Type | 1 byte       |
| Target Port Number | 2 bytes      |
| Start Time | 8 bytes      |
| Expiration Time | 8 bytes      |
| Target Username | 32 bytes     |
| Target SNI      | <=256 bytes  |
| Delegate Client Certificate | <= 660 bytes |
| Associated Data | * bytes      |

- **Target Username** (32 bytes): the user on the target server that the Delegate wants to perform the action as (*as whom*). Populated by DClient from default (local username) or CLI flags/config.
- **Target SNI** (<=256 bytes): the identifier of the server that the Delegate wants to connect to (*to whom*). In the format of a cert ID Block. Populated by DClient from CLI flags/config.
- **Target Port Number** (2 bytes): what port to connect to on the target. Populated by DClient from default or CLI flags/config.
- **Grant Type** (1 byte): indicates how to interpret the "Associated Data" section. Can be one of "shell", "cmd", "local PF", "remote PF", etc. Populated by DClient. 
- **Start Time** (8 bytes): timestamp of when the authorization grant becomes effective.
- **Expiration Time** (8 bytes): timestamp of when the authorization grant expires.
- **Delegate Client Certificate** (<= 660 bytes): "self-signed" or otherwise; contains Delegate's static public key.
- **Associated Data** (* bytes): More information about specific action (e.g. command to run, ports to forward, etc.)


### Authorize Intent

Upon receiving the Intent Request from ServerA, PClient needs to either approve or deny the request presented by the intent dialogue.

```
Would you like to
  allow delegate.server.com
  to run the command 'sudo reboot'
  as user
  on target.server.com
  from <date>
  until <date>
  
    Yes
  > No
```


If the Intent Request is denied, then PClient sends an Intent Denied message with an optional reason for the denial. It keeps the AGT open in case the Delegate would like to send more Intent Requests.

### Intent Communication

- Assuming the Principal approves the Intent Request, then it needs to communicate the Intent Request to the target server (ServerB).
- It does this by establishing a hop session with the target proxied through the Delegate (it is not required that the Principal be able to directly connect to the target server).
- The Principal verifies that the target server's certificate matches the Target SNI field in the Intent Request, and then sends the Intent Request over.

### Intent Confirmation or Denial

- The target server (ServerB) verifies that the Principal (PClient) has sufficient authority to grant the request and otherwise ensures that the request is acceptable.
- If the target agrees to authorize the request then it stores the  *authorization grant* (consisting of data from the Intent Request) in an in-memory map of Client Identifiers (static public keys) --> authorization grants[].
- It sends back an Intent Confirmation or an Intent Denied (with optional reason) back to the Principal. The Principal forwards this response to the Delegate.

### DClient connects to ServerB (target)

- Now, upon completing the transport layer handshake with ServerB (using the keypair/cert corresponding to the client identifier for the authgrants), DClient can use any of the authgrants to perform authorized actions on the client. As authgrants are used/expire, ServerB (Target) removes them from the authgrant map.
