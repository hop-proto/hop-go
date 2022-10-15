## Secure Identity Forwarding (Authorization Grant Protocol)

Hop seeks to provide native support for secure identity forwarding that abides by the Secure Delegation Principal outlined by Kogan et al. In contrast to ssh-agent identity forwarding, Hop seeks to avoid exposing agents to unauthenticated key challenges and to provide fine-grained control over how the principal identity is used by semi-trusted delegates.

**Secure Delegation Principle**: The delegate is only able to act under the principal's authority after the principal can verify and enforce the delegate's intent. The intent consists of 4 components (will be discussed in much greater detail below):
1. **Who** (the delegate)
2. **What** (the action)
3. **To Whom** (the target)
4. **When** (deadline/expiration date)

On inception a hop client process determines whether it is acting as a Principal (P) or Delegate (D). The default behavior is for the hop client to be a D (TODO(baumanl): confirm this is desired default), but this can be overriden via the client config file or command line arguments.

**Principal** Client:
- must have proof of identity (e.g. cert + static private key)
- handles requests for authorization grants from delegates

**Delegate** Client:
- must request an authorization grant from a Principal Client
- must be a descendant process of hopd
- to request an auth grant: hopd must still have an active hop session with a P hop client (once an auth grant has been issued the hop session with the principal can terminate, but no further auth grants can be granted and further identity chaining will not be possible.)

## Authgrant Flow

```sequence
PClient-->ServerA: Principal connects to ServerA
...
DClient--ServerA-->PClient: Intent Request
Authorize Intent
PClient--ServerA-->ServerB: Intent Communication
ServerB--ServerA--PClient--ServerA-->DClient: Intent Confirmation
PClient-->ServerB: Delegate connects to ServerB
```
I made a rudimentary animation of this process in google slides (present and click through animations). The demo is [here](https://docs.google.com/presentation/d/1ko2Q3L3h53x7km9UPEJ0RhSkpTbN8zR1naasRe5R1kE/edit#slide=id.g16983377a29_0_217)

### Principal Client Connects to ServerA
- Principal client performs a standard hop handshake with serverA and starts a hop session
- within this hop session the user starts a Delegate Hop Client on Server A. (e.g. hopd--bash(PID)--hop or just hopd--hop(PID) if executing a single command)
- hopd adds an entry to a map of PID --> hop session with principal
- hopd listens on an abstract unix domain socket for requests from descendent processes to contact their respective principal

### Intent Request

- The delegate client (DClient) uses IPC to contact the hopd server (ServerA) and request to send an intent request to its principal (PClient)
- ServerA verifies that DClient is a descendent process and uses it's PID to locate the hop session it has with its principal. TODO(baumanl): this portion of code is very unix specific --> either generalize or weaken this guarantee.
- ServerA opens an authorization grant tube (AGT) with PClient and sends the intent request message (outlined below).

### Intent Request Fields

| Field           | Size        |
| -----------     | ----------- |
| Target Username | 32 bytes    |
| Target SNI      |  256 bytes       |
| Target Port Number | 2 bytes |
| Grant Type | 1 byte |
| Reps | 1 byte|
| Start Time | 8 bytes |
| Expiration Time | 8 bytes |
| Delegate Client Certificate | <= 660 bytes (?)|
| Associated Data | * bytes |

- **Target Username** (32 bytes): the user on the target server that the delegate wants to perform the action as (the *to whom* or *as whom* I guess). Populated by DClient from default (local username) or CLI flags/config.
- **Target SNI** (256 bytes): the identifier of the server that the delegate wants to connect to (the other part of the *to/as whom*). In the format of a cert ID Block. Populated by DClient from CLI flags/config.
- **Port** (2 bytes): what port to connect to on the target. Populated by DClient from default or CLI flags/config.
- **Grant Type** (1 byte): indicates how to interpret the "Associated Data" section. Can be one of "shell", "cmd", "local PF", "remote PF", etc. Populated by DClient. TODO(baumanl): is this actually necessary/how was I using it exactly before...?
- **Reps** (1 byte): How many times this authorization grant can be used (single use or multi-use). Don't know if we care about this or if we should allocate more than one byte.
- **Start Time** (8 bytes): timestamp of when the authorization grant becomes effective.
- **Expiration Time** (8 bytes): timestamp of when the authorization grant expires.
- **Delegate Client Certificate** (<= 660 bytes): "self-signed" or otherwise; contains delegate's static public key.
- **Associated Data** (* bytes): More information about specific action (e.g. command to run, ports to forward, etc.)


**TODO**(baumanl): Previously the intent request was missing some concept of the "when" (start time, duration, repeatability of the grant). What exactly do we want to support/what should the defaults be? I added the Reps, Start Time, and Duration fields to account for this, but they were not mentioned in the original outline of the auth grant protocol and I did not implement them previously.

### Authorize Intent

- upon receiving the IR from ServerA, PClient needs to either approve or deny the request. This could be accomplished in many ways (e.g. prompting user for approval, reading a "policy" file, etc.)
- If the IR is denied, then PClient sends an Intent Denied message with an optional reason for the denial. It keeps the AGT open in case the Delegate would like to send more IRs.

### Intent Communication

- Assuming the Principal approves the IR, then it needs to communicate the IR to the target server (ServerB).
- It does this by establishing a hop session with the target proxied through the delegate (it is not required that the principal be able to directly connect to the target server).
- The principal verifies that the target server's certificate matches the Target SNI field in the IR, and then sends the IR over.

### Intent Confirmation or Denial

- The target server (ServerB) verifies that the principal (PClient) has sufficient authority to grant the request and otherwise ensures that the request is acceptable.
- If the target agrees to authorize the request then it stores the  *authorization grant* (consisting of data from the intent request) in an in-memory map of Client Identifiers --> authorization grants[]. TODO(baumanl): what should the keys for this map actually be? Full client cert seems excesive, just keep as SHA3(delegate_static_public_key)?
- It sends back an Intent Confirmation or an Intent Denied (with optional reason) back to the Principal. The Principal forwards this response to the Delegate.

### DClient connects to ServerB (target)

- Now, upon completing the transport layer handshake with ServerB (using the keypair/cert corresponding to the client identifier for the authgrants), DClient can use any of the authgrants to perform authorized actions on the client. As authgrants are used/expire, ServerB (Target) removes them from the authgrant map.

- TODO(baumanl): In order for an authgrant to be used, the delegate must be able to complete a hop handshake with the server. This brings up the concern of client authentication. If the delegate is using a self-signed certificate (basically a wrapper around a temporary "static" key) then the server must be willing to complete the handshake even though there is no real client certificate involved. This has a few implications that I see:
  1. If the hop server does not want to trust self-signed certificates, then the delegate client must have access to a static key and certificate that the transport layer will accept. Then, after the handshake, it can have an authorization grant giving it temporary access from another user. This seems borderline redundant and like it could potentially cause issues if a delegate cert is given too much baseline power. However, currently I think this is the correct approach for cases where the hop server is configured to not allow self-signed connections.
  2. On the otherhand, if the server always completes handshakes with all self-signed certificates then it seems like client certs are somewhat pointless to begin with.
  3. Or, and this would probably involve breaking layering, we could attempt to allow the hop transport layer can trust self-signed certs only in the case that they have a corresponding outstanding authgrant.

###

Other Discussion Points:
- TODO(baumanl): are all of the fields in the Intent Request necessary/are any missing? Specifically, it used to also include the Delegate SNI, but I think the principal should actually just keep track of it since it will have received the Delegate's certificate when connecting to it.
- TODO(baumanl): any use case for attempting to *dynamically* determine whether a client should act as a P/D? (e.g. by determining if it was spawned by a hopd process?)
- TODO(baumanl): specify threat model better (how much do we trust the delegate/authorization grant requests that the principal receives?

Questions about Client Certs:
- Minimum number of bytes?
- Use cases for multiple ID blocks?
