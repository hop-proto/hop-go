# SSH Protocol



[TOC]

Draft Authors: Wilson Nguyen, Gerry Wan, David Adrian, Zakir Durumeric

## Prerequisite Knowledge

### Permutation Based Cryptography

A cryptographic library often is an amalgamation of symmetric cryptographic implementations (AES-GCM, CHACHA-Poly1305, SHA3, SipHash, BLAKE2, HKDF, HMAC). This has caused a combinatorial explosion of mixing and matching and increased code complexity and code size.

> *A **random permutation** is sufficient to implement a majority of symmetric cryptographic primitives*

Therefore, we can significantly reduce code complexity, size, and proofs by building crypto off of a single permutation. Additionally, computation over prefixes of data already computed are zero cost.

### Duplex Object Intro

---

A [**sponge function**](https://keccak.team/sponge_duplex.html) is a generalization of a hash function that provides extendable output as a truncated random oracle.

> The term *sponge* is used to because these functions **absorb** input material and **squeeze** output material

>  **Example:** SHA3 is a fixed-size output sponge function based upon the **keccak** permutation.

A sponge function can be described as $F: \mathbb{Z}_2^*\rightarrow\mathbb{Z}_2^*$ parameterized by $r$ (rate), $c$ (capacity), and an $n$-bit permutation $f$. The capacity $c$-bits of a sponge function is the private state of the permutation.

<img src="https://keccak.team/images/Sponge-150.png" alt="sponge construction" style="zoom: 67%;" />

> $F(M)=Z$ is computed by absorbing $r$-bit chunks of $M$ and squeezes out $r$-bit chunks of $Z$.

A **duplex object** is a construction related to sponge functions that allow for [incrementality](https://archive.fosdem.org/2020/schedule/event/security_incrementality_and_deck_functions/).

<img src="https://keccak.team/images/Duplex-150.png" alt="sponge construction" style="zoom:67%;" />

> The duplex object absorbs $\sigma_i$ and outputs $Z_i$. Note that $Z_i$ depends on all $\sigma_j$ for $j<i$.

The duplex object can be used to implement PRFs, hash functions, eXentable output functions (XOFs), authenticated encryption, macs, AD, KDFs and supports ratchet operations. Since duplex objects are incremental, they provide a natural session mode that authenticates the full transcript of operations.

> [Strobe](https://eprint.iacr.org/2017/003) (RWC 2017) implementation of a duplex object.

We will use the [Cyclist](https://eprint.iacr.org/2018/767.pdf) implementation of a duplex object instantiated with the **keccak** permutation.

The following primitive is not necessary to understand deeply.  For completion, we will include it because it provide us a a robust CTR mode AEAD over data of arbitrary size.

A [**deck function**](https://archive.fosdem.org/2020/schedule/event/security_incrementality_and_deck_functions/attachments/slides/3725/export/events/attachments/security_incrementality_and_deck_functions/slides/3725/InDF_FOSDEM2020.pdf) $F_K: \mathbb{(Z_2^*)^*\rightarrow (Z_2^n)^*}$ is a doubly extendable cryptographic keyed function.
$$
Z=0^n + F_K\big(X^{(m)}\circ X^{(m-1)} \circ ...\circ  X^{(1)}\big) << q
$$

- Input: a sequence of strings $X^{(m)}, X^{(m-1)}, ..., X^{(1)}$
- Output:
  - PRF of the input
  - $Z$ is the concatenation of $n$ bit chunks and is practically infinite

Deck functions enable a session supporting and nonce based AEAD encryption mode called **Deck-SANE**.

We will instantiate Deck-SANE in a CTR based mode with Kravatte as the deck function. To do this, we will use a CTR as the starting nonce and use Deck-SANE in a [stateless mode](https://keccak.team/2020/stateless_deck_based_modes.html).

> Thank you to Seth Hoffert for the suggestion and bounding pointers.

### Noise Protocol Intro

---

[Noise](http://www.noiseprotocol.org/noise.html) is a framework for crypto protocols based on Diffie-Hellman key agreement.

A Noise protocol begins with two parties exchanging **handshake messages**. During this **handshake phase** the parties exchange DH public keys and perform a sequence of DH operations, hashing the DH results into a shared secret key. After the handshake phase each party can use this shared key to send encrypted **transport messages**. Noise separately keeps a hash chain of the transcript for post-handshake verification.

Let $s$ and $e$ represent static and ephemeral DH key pairs respectively. The static key pair will be used to establish identity.

Let $ee, es, se, ss$ represent $\text{DH}(e, e), \text{DH}(e,s), ...$ where the left is client and right is server.

Noise uses **handshake patterns** to describe different handshakes. Here is an example of normal DH handshake:

$\rightarrow e$

$\leftarrow e, ee$

> Client sends to server it's ephemeral DH public key, the server sends to client it's ephemeral DH public key, and both parties perform $\text{DH}(e,e)$ and absorb this into a KDF and hash transcript chain.

We will use the following handshake patterns:

**IK (1-RTT)**

$\leftarrow s$

---

$\rightarrow e, es, s, ss$

$\leftarrow e, ee, se$

**XX (1.5 RTT)**

$\rightarrow e$

$\leftarrow e, ee, s, es$

$\rightarrow s, se$

> After each DH operation, everything is encrypted with an AEAD cipher keyed with keys derived from the chain of DH output values. For example, in the **IK** handshake pattern, $s$ is encrypted as $\text{AEAD}(\text{KDF}(\text{DH}(e,s))), s)$, while the encryption of the server ephemeral key is under a key derived from $es$ and $ss$.

### Noise + Duplex Objects

---

The state machine for Noise involves two separate chains for the protocol transcript and key derivation.

A duplex object allows us to reduce the state machine to a single chain and authenticate the whole transcript with tags.

> The [Disco framework](https://discocrypto.com/#/) (above) is an example of Noise using duplex objects.

Our protocol will incorporate the [Cyclist](https://eprint.iacr.org/2018/767.pdf) duplex object with Noise.

## Handshake Description

### Discoverable Server Flow

---

```sequence
Client->Server: Client Hello [0x1]
Server->Client: Server Hello [0x2]
Client->Server: Client Ack [0x3]
Server->Client: Server Auth [0x4]
Client->Server: Client Auth [0x5]
Client->Server: Transport Data [0x6]
Server->Client: Transport Data [0x6]
```

### Message Structures

---

Squeeze will always squeeze a 16-byte MAC.

Note that `absorb([a, b])`operates on the concatenation of `a` and `b`, and should be read as `absorb(''.join(a, b))`. It does not result in the same state as `absorb(a); absorb(b)`.

#### Client Hello Message

---

|        type $:=$ 0x1 (1 byte)        | Protocol Version (1 byte) | reserved $:= 0^2$ (2 bytes) |
| :----------------------------------: | :-----------------------: | --------------------------- |
| Client ephemeral $:= e_c$ (32 bytes) |      mac (16 bytes)       |                             |

##### Client Hello Construction

---

- $I_c$ is a 32 bit random index similar to IPsec's Security Parameter Index (SPI). This is used to identify sessions. TODO: what is this?
- ephemeral is set to the client ephemeral public key.

```python
protocolName = “hop_NN_XX_cyclist_keccak_p1600_12” # 1-1 protocol version
duplex = Cyclist()
duplex.absorb(protocolName)

duplex.absorb([type, version, reserved])
duplex.absorb(ephemeral)
mac = duplex.squeeze()
```

##### Server Logic

---

```python
duplex = Cyclist()
duplex.absorb(protocolName)
duplex.absorb([type, version, reserved])
duplex.absorb(e_c)
mac = duplex.squeeze()
```

- Calculated mac ?= client mac
  - If so, send Server Hello
  - Else: do not respond

#### Server Hello Message

---

|        type $:=$ 0x2 (1 byte)        |                 reserved $:= 0^3$ (3 bytes)                  |
| :----------------------------------: | :----------------------------------------------------------: |
| Server Ephemeral $:= e_s$ (32 bytes) | cookie = AEAD($K_r$, $e_s$, H($e_c$, clientIP, clientPort)) (32 +16 + 12 bytes) |
|            mac (16 bytes)            |                                                              |

##### Server Hello Construction

---

- $K_r$ is a key that is rotated every N minutes or M connections

```python
# Continuing from duplex prior
duplex.absorb(type + reserved)
duplex.absorb(e_s)
duplex.absorb(DH(ee))

# AEAD Construction
H = SHA3.256
aead = SANE_init(K_r)
data, tag = aead.seal(plaintext=e_s.private, ad=H(e_c, clientIP, clientPort))
cookie = data + tag
duplex.absorb(cookie)
mac = duplex.squeeze()
```
TODO: the number of cookie bytes differs in the paper.
We'll want to adjust nonce sizes once we're using SANE (/if we don't end up using SANE). It would be nice to get the cookie down to 48 bytes.

##### Client Logic

---

```python
# Continuing from duplex prior
duplex.absorb([type, reserved])
duplex.absorb(e_s)
duplex.absorb(DH(ee))
duplex.absorb(cookie)
mac = duplex.squeeze()
```

- Is the mac the same?

#### Client Ack

---

| type $:=$ 0x3 (1 byte) | reserved $:= 0^3$ (3 bytes) |
| :--------------------: | :-------------------------: |
|    $e_c$ (32 bytes)    |      cookie (60 bytes)      |
|    SNI (256 bytes)     |       mac (16 bytes)        |

##### Client Construction

---

- SNI is an IDBlock from the certificate spec
  - Server ID is the expected ID of the server

```python
# Continuing from duplex prior
duplex.absorb([type, reserved])
duplex.absorb(e_c)
duplex.absorb(cookie)
sni = padTo(serverID, 256) # pad serverID to 256 bytes
duplex.enc(sni)
mac = duplex.squeeze()
```

##### Server Logic

---

```python
# Use cookie AEAD construction
e_s = aead_open(nonce=cookie[:12], ciphertext=cookie[12:], ad=H(e_c, clientIP, clientPort))
# ... Resimulate duplex up until this point ...
duplex.absorb([type, reserved])
duplex.absorb(e_c)
duplex.absorb(cooke)
sni = duplex.decrypt(encrypted_sni)
name = unPad(sni)
duplex.squeeze()
```

- Use SNI to located certificate to serve, verify all macs
- Limit max number of handshakes with a given IP
- Only read the SNI if the Mac matches

#### Server Auth

---

| type $:=$ 0x4 (1 byte) |     Reserved := 0 (1 byte)     | Certs Len (2 bytes)                    |
| :--------------------: | :----------------------------: | -------------------------------------- |
|  SessionID (4 bytes)   | Leaf Certificate (2 + n bytes) | Intermediate Certificate (2 + n bytes) |
|     tag (16 bytes)     |         mac (16 bytes)         |                                        |
|                        |                                |                                        |

- Certs Len is the length of the encrypted section
- Each certificate is encoded as a vector with a 2-byte length prepended
  - Total `certsLen := 4 + len(leaf) + len(intermediate)`
- SessionID is a random unique 4 byte opaque string, generated by the server

##### Server Auth Construction

---

```python
# Continuing from duplex prior
duplex.absorb(type + reserved + certsLen)
duplex.absorb(sessionID)
certificates := [len(leaf), leaf, len(intermediate), intermediate]
encCerts = duplex.encrypt(certificates)
tag = duplex.squeeze()
duplex.absorb(DH(es))
mac = duplex.squeeze()
```

Client Logic

---

```python
# Continuing from duplex prior
duplex.absorb(type, reserved + certsLen)
duplex.absorb(SessionID)
certificates = duplex.decrypt(encCerts)
tag = duplex.squeeze()
# verify tag
# verify certs, extract server s
duplex.absorb(DH(es))
mac = duplex.squeeze()
```

- Verify the tag before parsing the certs
- Quit the handshake if the certs are invalid
- Is the mac the same (after DH)

#### Client Auth
OUT OF DATE

---

| type $:=$ 0x5 (1 byte) | reserved $:= 0^3$ (3 bytes) |
| :--------------------: | :-------------------------: |
|  SessionID (4 bytes)   | encrypted static (32 bytes) |
|     tag (16 bytes)     |       mac (16 bytes)        |

##### Client Auth Construction

---

```python
# Continuing from duplex prior
duplex.absorb([type, reserved])
duplex.absorb(SessionID)
encStatic = duplex.encrypt(static)
tag = duplex.squeeze()
duplex.absorb(DH(se))
mac = duplex.squeeze()
```

##### Server Logic

---

```python
# Continuing from duplex prior
duplex.absorb([type, reserved])
duplex.absorb(SessionID)
static = duplex.decrypt(encStatic)
tag = duplex.squeeze(tag)
# Verify tag
duplex.absorb(DH(se))
mac = duplex.squeeze()
```

- Is the static a static of a valid client?
- Verify the tag before doing DH
- Is the mac the same (after DH)

#### Transport Message

---

##### Client & Server Key Derivation

---

```python
duplex.ratchet()
duplex.absorb("client_to_server_key")
client_to_server_key = duplex.squeeze_key() # squeeze 16
duplex.ratchet()
duplex.absorb("server_to_client_key")
server_to_client_key = duplex.squeeze_key() # squeeze 16
# Every 2^64 payloads these keys will rotate
# TODO(dadrian): Define how
```

##### Message

|  type $:=$ 0x6 (1 byte)  | reserved $:= 0^3$ (3 bytes) |
| :----------------------: | :-------------------------: |
|   SessionID (4 bytes)    |      Counter (8 bytes)      |
| Encrypted Data (* bytes) |                             |

Counter is a literal counter. Is not a nonce.

Encrypted data will contain a nonce at the front, if necessary, and a Mac. The AEAD implementation should verify the mac as part of the open/seal.

##### Transport Construction

---

```python
# Eventually
# aead = SANE_init(server_to_client_key, counter)
# Now
aead = aes_gcm(key, nonce_size=12)
nonce = getrandombytes(12)
enc_data = aead(plaintext=plaintext, nonce=nonce, ad=pkt[0:headerLen + SessionIDLen + CounterLen])
enc_data = ''.join([nonce, enc_data])
counter +=1
```

### WIP: Hidden Server Flow

---

```sequence
Client->Server: Client Auth [0x7]
Server->Client: Server Auth [0x8]
Client->Server: Transport Data [0x6]
Server->Client: Transport Data [0x6]
```

TODO(dadrian): Implement and update docs

### Message Structures

---

#### Client Auth Message
TODO: also out of date (need client certs)
---

|   type $:=$ 0x7 (1 byte)    |  Protocol Version (1 byte)  |
| :-------------------------: | :-------------------------: |
| reserved $:= 0^2$ (2 bytes) | client ephemeral (32 bytes) |
|  client static (32 bytes)   |       tag (16 bytes)        |
|    Timestamp (12 bytes)     |       mac (16 bytes)        |

##### Client Auth Construction

---

```python
protocolID = “noise_IK_cyclist_keccak_C512”
duplex = Cyclist()
duplex.absorb(protocolID)
duplex.absorb([type, protocol, reserved, ephemeral])
duplex.absorb(DH(es))
static = duplex.encrypt(s)
tag = duplex.squeeze()
duplex.absorb(ss)
timestamp = duplex.encrypt(TAI64N())
mac = duplex.squeeze()
```

- Timestamp: [TAI64N](https://cr.yp.to/libtai/tai64.html)
  - 8 bytes (seconds) || 4 bytes (nanoseconds)
  - Necessary to prevent replay of Client Hello to trigger server response.

##### Server Logic

---

```python
protocolID = “noise_IK_cyclist”
duplex = Cyclist()
duplex.absorb(protocolID)
duplex.absorb([type, protocol, reserved, ephemeral])
duplex.absorb(DH(es))
static = duplex.decrypt(s, tag)
duplex.absorb(ss)
timestamp = duplex.decrypt(TAI64N(), mac)
```

- Is the static a static of a valid client?
- Is the timestamp greater than the last timestamp seen from the last valid handshake from the client?
- Search up certificate related to serverID for that serverID type

#### Server Auth Message

---

|   type $:=$ 0x8 (1 byte)   |   Leaf Certificate Bytes (2 bytes)   |
| :------------------------: | :----------------------------------: |
|  reserved $:= 0$ (1 byte)  |                                      |
|    SessionID (4 bytes)     | Server Ephemeral $:= e_s$ (32 bytes) |
| Leaf Certificate (* bytes) |  Intermediate Certificate (* bytes)  |
|       tag (16 bytes)       |            mac (16 bytes)            |

##### Server Auth Construction

---

```python
# Continuing from duplex prior
duplex.absorb([type, reserved, sessionID])
duplex.absorb(DH(ee))
certificates = duplex.encrypt(certificates)
tag = duplex.squeeze()
duplex.absorb(DH(se))
mac = duplex.squeeze()
```

##### Client Logic

---

```python
# Continuing from duplex prior
duplex.absorb([type, reserved, sessionID])
duplex.absorb(DH(ee))
certificates = duplex.decrypt(certificates, tag)
duplex.absorb(DH(se))
mac = duplex.squeeze()
```

- Are the certificates valid?
- Is the mac the same?

#### Transport Message

---

|  type $:=$ 0x6 (1 byte)  | reserved $:= 0^3$ (3 bytes) |
| :----------------------: | :-------------------------: |
|   SessionID (4 bytes)    |      Counter (8 bytes)      |
| Encrypted Data (* bytes) |       Mac (16 bytes)        |

- Logic same as discoverable flow, but continuing from duplex above

## Local Trust Splitting

The noise protocol authenticates the client using a static DH key pair. However, we would like to locally split trust across multiple feeds. For example, we may want authentication to require both a yubikey and a key pair stored on the client device. Yubikey keys have a [restricted API](https://support.yubico.com/support/solutions/articles/15000027139-yubikey-5-2-3-enhancements-to-openpgp-3-4-support) of operations that provide both signing and DH oracles. Therefore, our local trust splitting can only depend on this restricted API; in our trust splitting protocol, we will model local key pairs as DH oracles that support the following operation:

- For key pair $(\alpha, \alpha G)$, where $G$ is the generator of a prime order group,  $\mathcal{O}_{\alpha}(X)=\alpha X$.

We require that loss of a single DH oracle prevents us from calculating a shared secret with a remote party.

> Note: the use of ephemeral keys in the key agreement preserves forward secrecy.

To split trust, we simply just create a DH oracle $\mathcal{O}_\beta$, where $\beta = \alpha_1\alpha_2...\alpha_n$ for private keys $\alpha_1, ..., \alpha_n$. To do this, we simply compose the DH oracles as follows:
$$
\mathcal{O}_\beta (X) = \mathcal{O}_{\alpha_1}\mathcal{O}_{\alpha_2}...\mathcal{O}_{\alpha_n}(X)
$$
Thus, to a remote party, the client appears to have local key pair $\beta, \beta G$.


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
