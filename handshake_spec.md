# Hop Protocol



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
Client->Server: Transport Data [0x20]
Server->Client: Transport Data [0x20]
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

duplex.absorb([type + version + reserved])
duplex.absorb(ephemeral)
mac = duplex.squeeze()
```

##### Server Logic

---

```python
duplex = Cyclist()
duplex.absorb(protocolName)
duplex.absorb([type + version +reserved])
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
duplex.absorb([type + reserved])
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
duplex.absorb([type + reserved])
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
duplex.absorb([type + reserved])
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
duplex.absorb(type + reserved + certsLen)
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

| type $:=$ 0x5 (1 byte) |     Reserved := 0 (1 byte)     | Certs Len (2 bytes)                    |
| :--------------------: | :----------------------------: | -------------------------------------- |
|  SessionID (4 bytes)   | Leaf Certificate (2 + n bytes) | Intermediate Certificate (2 + n bytes) |
|     tag (16 bytes)     |         mac (16 bytes)         |                                        |
|                        |                                |                                        |


##### Client Auth Construction


```python
# Continuing from duplex prior
duplex.absorb(type + reserved + certsLen)
duplex.absorb(sessionID)
certificates := [len(leaf), leaf, len(intermediate), intermediate]
encCerts = duplex.encrypt(certificates)
tag = duplex.squeeze()
duplex.absorb(DH(se))
mac = duplex.squeeze()
```


##### Server Logic

---

```python
# Continuing from duplex prior
duplex.absorb(type +  reserved + certsLen)
duplex.absorb(SessionID)
certificates = duplex.decrypt(encCerts)
tag = duplex.squeeze()
# verify tag
# verify certs, extract server s
duplex.absorb(DH(se))
mac = duplex.squeeze()
```
- Verify the tag before parsing the certs
- Quit the handshake if the certs are invalid
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

### Hidden Server Flow

---


```sequence
Client->Server: Client Auth [0x8]
Server->Client: Server Auth [0x9]
Client->Server: Transport Data [0x20]
Server->Client: Transport Data [0x20]
```

### Message Structures

---

##### Client Auth Message

---

|      type $:=$ 0x8 (1 byte)       |          Protocol Version (1 byte)          |       Certs Len $:= 0^2$ (2 bytes)        |
|:---------------------------------:|:-------------------------------------------:|:-----------------------------------------:|
|                                   |         Client Ephemeral (32 bytes)         |                                           |
| Client Leaf Certificate (* bytes) |                                             | Client Intermediate Certificate (* bytes) |
|                                   | Client Static Authentication Tag (16 bytes) |                                           |
|                                   |             Timestamp (8 bytes)             |                                           |
|                                   |               MAC (16 bytes)                |                                           |

##### Client Auth Construction

---

TODO check the protocol ID in the code and here

```python
# server’s static key is cached from a previous discoverable mode handshake, or distributed out-of-band
protocolID = “noise_IK_cyclist_keccak_C512”
duplex = Cyclist()
duplex.absorb(protocolID)
duplex.absorb([type + protocol + reserved])
duplex.absorb(ClientEphemeral)
duplex.absorb(DH(es))
ClientEncCerts = duplex.encrypt(certificates)
tag = duplex.squeeze()
duplex.absorb(ss)
timestamp = duplex.encrypt(time.Now().Unix())
mac = duplex.squeeze()
```

##### Server Logic

---

```python
protocolID = “noise_IK_cyclist_keccak_C512”
duplex = Cyclist()
duplex.absorb(protocolID)
duplex.absorb([type + protocol + reserved])
duplex.absorb(ClientEphemeral)
duplex.absorb(DH(es))
certificates = duplex.decrypt(ClientEncCerts)
tag = duplex.squeeze()
# verify tag
# verify certs, extract client static
duplex.absorb(ss)
timestamp = duplex.decrypt(time.Now().Unix())
mac = duplex.squeeze()
```

- Is the static a static of a valid client? (what do we consider as a valid client?)
- Is the timestamp greater than the last timestamp seen from the last valid handshake from the client?
- Search up certificate related to serverID for that serverID type (not implemented yet -> server will loop in the SNI to find the corresponding key)

#### Server Auth Message

---


|      type $:=$ 0x8 (1 byte)       |       Reserved $:= 0$ (1 byte)       |       Certs Len $:= 0^2$ (2 bytes)        |
|:---------------------------------:|:------------------------------------:|:-----------------------------------------:|
|                                   |         SessionID (4 bytes)          |                                           |
|                                   |     Server Ephemeral (32 bytes)      |                                           |
| Server Leaf Certificate (* bytes) |                                      | Server Intermediate Certificate (* bytes) |
|                                   | Server Authentication Tag (16 bytes) |                                           |
|                                   |            MAC (16 bytes)            |                                           |


##### Server Auth Construction

---

```python
# Continuing from duplex prior
duplex.absorb([type + reserved + Certs Len])
duplex.absorb(SessionID)
duplex.absorb(ServerEphemeral)
duplex.absorb(DH(ee))
ServerEncCerts = duplex.encrypt(certificates)
tag = duplex.squeeze()
duplex.absorb(DH(se))
mac = duplex.squeeze()
```

##### Client Logic

---

```python
# Continuing from duplex prior
duplex.absorb([type + reserved + Certs Len])
duplex.absorb(SessionID)
duplex.absorb(ServerEphemeral)
duplex.absorb(DH(ee))
certificates = duplex.decrypt(ServerEncCerts)
tag = duplex.squeeze()
# verify tag
# verify certs, extract server static
duplex.absorb(DH(se))
mac = duplex.squeeze()
```

- Are the certificates valid? (TODO paul)

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



## Post Quantum Handshake Description

### Discoverable Server Flow

---

```sequence
Client->Server: Client Hello [0x11]
Server->Client: Server Hello [0x12]
Client->Server: Client Ack [0x13]
Server->Client: Server Auth [0x14]
Client->Server: Client Auth [0x15]
Server->Client: Server Conf [0x16]
Client->Server: Transport Data [0x20]
Server->Client: Transport Data [0x20]
```

#### Client Hello Message

---

|        type $:=$ 0x11 (1 byte)        | Protocol Version (1 byte) | reserved $:= 0^2$ (2 bytes) |
|:-------------------------------------:| :-----------------------: | --------------------------- |
| Client ephemeral $:= e_c$ (800 bytes) |      mac (16 bytes)       |                             |

##### Client Hello Construction

---

```python
protocolName = “hop_pqNN_XX_cyclist_keccak_p1600_12” # 1-1 protocol version
duplex = Cyclist()
duplex.absorb(protocolName)

duplex.absorb([type + version + reserved])
duplex.absorb(ephemeral)
mac = duplex.squeeze()
```

##### Server Logic

---

```python
duplex = Cyclist()
duplex.absorb(protocolName)
duplex.absorb([type + version +reserved])
duplex.absorb(e_c)
mac = duplex.squeeze()
```

- Calculated mac ?= client mac
  - If so, send Server Hello
  - Else: do not respond

#### Server Hello Message

---

|                                 type $:=$ 0x12 (1 byte)                                 |                 reserved $:= 0^3$ (3 bytes)                  |
|:---------------------------------------------------------------------------------------:| :----------------------------------------------------------: |
| cookie = AEAD($K_r$, $ML-KEM Key seed$, H($e_c$, clientIP, clientPort)) (32 + 64 bytes) |            mac (16 bytes)            |

##### Server Hello Construction

---

- $K_r$ is a key that is rotated every N minutes or M connections

```python
# Continuing from duplex prior
duplex.absorb(type + reserved)

# AEAD Construction
H = SHA3.256
aead = SANE_init(K_r)
cookie = aead.seal(plaintext=e_s.seed, ad=H(e_c, clientIP, clientPort))
duplex.absorb(cookie)
mac = duplex.squeeze()
```

##### Client Logic

---

```python
# Continuing from duplex prior
duplex.absorb([type + reserved])
duplex.absorb(cookie)
mac = duplex.squeeze()
```

- Is the mac the same?

#### Client Ack

---

| type $:=$ 0x13 (1 byte) | reserved $:= 0^3$ (3 bytes) |
|:-----------------------:|:---------------------------:|
|    $e_c$ (800 bytes)    |      cookie (96 bytes)      |
|     SNI (256 bytes)     |       mac (16 bytes)        |

##### Client Construction

---

- SNI is an IDBlock from the certificate spec
  - Server ID is the expected ID of the server

```python
# Continuing from duplex prior
duplex.absorb([type + reserved])
duplex.absorb(cookie)
sni = padTo(serverID, 256) # pad serverID to 256 bytes
duplex.enc(sni)
mac = duplex.squeeze()
```

##### Server Logic

---

```python
# Use cookie AEAD construction
seed = aead_open(ciphertext=cookie, ad=H(e_c, clientIP, clientPort))
e_s = kem.GenerateKeypairFromSeed(seed)
# ... Resimulate duplex up until this point ...
duplex.absorb([type + reserved])
duplex.absorb(cookie)
sni = duplex.decrypt(encrypted_sni)
name = unPad(sni)
duplex.squeeze()
```

- Use SNI to located certificate to serve, verify all macs
- Limit max number of handshakes with a given IP
- Only read the SNI if the Mac matches

#### Server Auth

---

| type $:=$ 0x14 (1 byte) |     Reserved := 0 (1 byte)     | Certs Len (2 bytes)                    |
|:-----------------------:|:------------------------------:|----------------------------------------|
|   SessionID (4 bytes)   | Leaf Certificate (2 + n bytes) | Intermediate Certificate (2 + n bytes) |
|     tag (16 bytes)      |      eKEM CT (768 bytes)       | mac (16 bytes)                         |
|                         |                                |                                        |

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
ct, k = kem.Enc(e_c)
duplex.absorb(k)
mac = duplex.squeeze()
```

Client Logic

---

```python
# Continuing from duplex prior
duplex.absorb(type + reserved + certsLen)
duplex.absorb(SessionID)
certificates = duplex.decrypt(encCerts)
tag = duplex.squeeze()
# verify tag
# verify certs, extract server s
k = kem.Dec(ct)
duplex.absorb(k)
mac = duplex.squeeze()
```

- Verify the tag before parsing the certs
- Quit the handshake if the certs are invalid
- Is the mac the same (after KEM)

#### Client Auth

| type $:=$ 0x15 (1 byte) |     Reserved := 0 (1 byte)     | Certs Len (2 bytes)                    |
|:-----------------------:|:------------------------------:| -------------------------------------- |
|   SessionID (4 bytes)   | Leaf Certificate (2 + n bytes) | Intermediate Certificate (2 + n bytes) |
|     tag (16 bytes)      |      sKEM CT (768 bytes)       |                 mac (16 bytes)                        |
|                         |                                |                                        |


##### Client Auth Construction


```python
# Continuing from duplex prior
duplex.absorb(type + reserved + certsLen)
duplex.absorb(sessionID)
certificates := [len(leaf), leaf, len(intermediate), intermediate]
encCerts = duplex.encrypt(certificates)
tag = duplex.squeeze()
ct, k = kem.Enc(s_s)
duplex.absorb(k)
mac = duplex.squeeze()
```


##### Server Logic

---

```python
# Continuing from duplex prior
duplex.absorb(type +  reserved + certsLen)
duplex.absorb(SessionID)
certificates = duplex.decrypt(encCerts)
tag = duplex.squeeze()
# verify tag
# verify certs, extract server s
k = kem.Dec(ct)
duplex.absorb(k)
mac = duplex.squeeze()
```
- Verify the tag before parsing the certs
- Quit the handshake if the certs are invalid
- Is the mac the same (after KEM)


#### Server Conf

| type $:=$ 0x16 (1 byte) | reserved $:= 0^3$ (3 bytes) |
|:-----------------------:|:---------------------------:|
|   sKEM CT (768 bytes)   |       mac (16 bytes)       |


##### Server Construction

```python
duplex.absorb([type + reserved])
ct, k = kem.Enc(c_s)
duplex.absorb(k)
mac = duplex.squeeze()
```

##### Client Logic

---

```python
duplex.absorb([type + reserved])
k = kem.Dec(ct)
duplex.absorb(k)
mac = duplex.squeeze()
```

- Is the mac the same (after KEM)
- Derives the keys and use regular transport messages