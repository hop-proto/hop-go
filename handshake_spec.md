# Hop Protocol

Authors: Paul Flammarion, George Ari Hosono, Wilson Nguyen, Laura Bauman, Daniel Rebelsky, Gerry Wan, David Adrian, Zakir Durumeric

## Prerequisite Knowledge

### Permutation Based Cryptography

---

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

The following primitive is not necessary to understand deeply.  For completion, we will include it because it provides us a robust CTR mode AEAD over data of arbitrary size.

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

### Post Quantum Noise

--- 

While the Noise Framework was originally designed to be instantiated with Diffie–Hellman key exchanges as its sole asymmetric primitive, Angel et al. proposed PQNoise as a post-quantum secure variant of the Noise Framework that substitutes Diffie–Hellman with Key Encapsulation Mechanisms (KEMs).

PQNoise replaces Diffie–Hellman in a secure way achieving both confidentiality and authenticity. Although this design prevents a man-in-the-middle adversary with post-quantum capabilities from compromising the session, recent NIST recommendations suggest postponing post-quantum authentication since current adversaries does not possess such capabilities. Consequently, an approach in which each cryptographic primitive serves a distinct security goal without conflating assumptions—is sufficient. In this setting, we can use KEMs exclusively to provide forward secrecy and protect against "harvest now, decrypt later" attacks by future quantum computers, while classical Diffie–Hellman is retained for authentication.

This approach significantly reduces the transmission overhead associated with large post-quantum KEM public keys and ciphertexts (especially considering the use of certificate chains), while still ensuring long-term post-quantum forward secrecy.

> [PQNoise](https://eprint.iacr.org/2022/539) (CCS '22)



### Noise + Duplex Objects

---

The state machine for Noise involves two separate chains for the protocol transcript and key derivation.

A duplex object allows us to reduce the state machine to a single chain and authenticate the whole transcript with tags.

> The [Disco framework](https://discocrypto.com/#/) (above) is an example of Noise using duplex objects.

Our protocol will incorporate the [Cyclist](https://eprint.iacr.org/2018/767.pdf) duplex object with Noise.




#### Transport Message

---

|  type $:=$ 0x6 (1 byte)  | reserved $:= 0^3$ (3 bytes) |
| :----------------------: | :-------------------------: |
|   SessionID (4 bytes)    |      Counter (8 bytes)      |
| Encrypted Data (* bytes) |       Mac (16 bytes)        |

- Logic same as discoverable flow, but continuing from duplex above


## Handshake Description

### Discoverable Server Flow

---

```sequence
Client->Server: Client Hello [0x01]
Server->Client: Server Hello [0x02]
Client->Server: Client Ack [0x03]
Server->Client: Server Auth [0x04]
Client->Server: Client Auth [0x05]
Client->Server: Transport Data [0x10]
Server->Client: Transport Data [0x10]
```

### Message Structures

---

Squeeze will always squeeze a 16-byte MAC.

Note that `absorb([a, b])`operates on the concatenation of `a` and `b`, and should be read as `absorb(''.join(a, b))`. It does not result in the same state as `absorb(a); absorb(b)`.

### Hop Noise PQ XX Pattern

---

We will denote e/skem for ML-KEM 512 keys, Encaps and Decaps are the function called with the keys, e/s are ephemeral and static keys used for the DH permutations.

```sequence
-> ekem
<- Encaps(ekem), cookie
-> e, ekem, cookie , Encrypt(SNI)
<- sessID, e, Encrypt(certs (s))  // compute DH(es)
-> sessID, Encrypt(certs (s))     // compute DH(se)
```


#### Client Hello Message

---

|             type $:=$ 0x01 (1 byte)             | Protocol Version (1 byte) | reserved $:= 0^2$ (2 bytes) |
|:-----------------------------------------------:| :-----------------------: | --------------------------- |
| Client ML-KEM Ephemeral $:= ekem_c$ (800 bytes) |      mac (16 bytes)       |                             |

##### Client Hello Construction

---

```python
protocolName = “hop_pqNN_XX_cyclist_keccak_p1600_12” # 1-1 protocol version
duplex = Cyclist()
duplex.absorb(protocolName)

duplex.absorb([type + version + reserved])
duplex.absorb(ekem_c)
mac = duplex.squeeze()
```

##### Server Logic

---

```python
duplex = Cyclist()
duplex.absorb(protocolName)
duplex.absorb([type + version +reserved])
duplex.absorb(ekem_c)
mac = duplex.squeeze()
```

- Calculated mac ?= client mac
  - If so, send Server Hello
  - Else: do not respond

#### Server Hello Message

---

|                                       type $:=$ 0x02 (1 byte)                                       |                 reserved $:= 0^3$ (3 bytes)                  |
|:---------------------------------------------------------------------------------------------------:|:------------------------------------------------------------:|
|                             ML-KEM 512 Ephemeral Ciphertext (768 bytes)                             |                                                              |
|   cookie = AEAD($K_r$, $ML-KEM shared secret$, H($ekem_c$, clientIP, clientPort)) (32 + 32 bytes)   |                        mac (16 bytes)                        |

##### Server Hello Construction

---

- $K_r$ is a key that is rotated every N minutes or M connections

```python
# Continuing from duplex prior
duplex.absorb(type + reserved)
ct, k = kem.Encaps(ekem_c)
duplex.absorb(k)


# AEAD Construction
H = SHA3.256
aead = SANE_init(K_r)
cookie = aead.seal(plaintext=k, ad=H(ekem_c, clientIP, clientPort)) // k -> ML-KEM shared secret
duplex.absorb(cookie)
mac = duplex.squeeze()
```

##### Client Logic

---

```python
# Continuing from duplex prior
duplex.absorb([type + reserved])
k = ekem_c.Decaps(ct)
duplex.absorb(k)
duplex.absorb(cookie)
mac = duplex.squeeze()
```

- Is the mac the same?

#### Client Ack

---

| type $:=$ 0x03 (1 byte) | reserved $:= 0^3$ (3 bytes) |
|:-----------------------:|:---------------------------:|
|    $e_c$ (32 bytes)     |     ekem_c (800 bytes)      |
|    cookie (64 bytes)    |                             |
|     SNI (256 bytes)     |       mac (16 bytes)        |

##### Client Construction

---

- SNI is an IDBlock from the certificate spec
  - Server ID is the expected ID of the server

```python
# Continuing from duplex prior
duplex.absorb([type + reserved])
duplex.absorb(e_c)
duplex.absorb(ekem_c)
duplex.absorb(cookie)
sni = padTo(serverID, 256) # pad serverID to 256 bytes
duplex.enc(sni)
mac = duplex.squeeze()
```

##### Server Logic

---

```python
# Use cookie AEAD construction
k = aead_open(ciphertext=cookie, ad=H(ekem_c, clientIP, clientPort))
# ... Resimulate duplex up until this point with k the previously shared secret...
duplex.absorb([type + reserved])
duplex.absorb(e_c)
duplex.absorb(ekem_c)
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

|        type $:=$ 0x04 (1 byte)         |     Reserved := 0 (1 byte)      | Certs Len (2 bytes)            |
|:--------------------------------------:|:-------------------------------:|--------------------------------|
|          SessionID (4 bytes)           |         e_s (32 bytes)          | Leaf Certificate (2 + n bytes) |
| Intermediate Certificate (2 + n bytes) |          tag(16 bytes)          | mac (16 bytes)                 |


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
duplex.absorb(e_s)
duplex.absorb(DH(ee))
certificates := [len(leaf), leaf, len(intermediate), intermediate]
encCerts = duplex.encrypt(certificates)
tag = duplex.squeeze()
duplex.absorb(DH(es))
mac = duplex.squeeze()
```

##### Client Logic

---

```python
# Continuing from duplex prior
duplex.absorb(type + reserved + certsLen)
duplex.absorb(SessionID)
duplex.absorb(e_s)
duplex.absorb(DH(ee))
certificates = duplex.decrypt(encCerts)
tag = duplex.squeeze()
# verify tag
# verify certs, extract server s
duplex.absorb(DH(es))
mac = duplex.squeeze()
```

- Verify the tag before parsing the certs
- Quit the handshake if the certs are invalid
- Is the mac the same

#### Client Auth

---

| type $:=$ 0x05 (1 byte) |     Reserved := 0 (1 byte)     | Certs Len (2 bytes)                    |
|:-----------------------:|:------------------------------:|----------------------------------------|
|   SessionID (4 bytes)   | Leaf Certificate (2 + n bytes) | Intermediate Certificate (2 + n bytes) |
|     tag (16 bytes)      |                                | mac (16 bytes)                         |


##### Client Auth Construction

---


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
- Derives the keys and use regular transport messages



### Hidden Mode Flow

---


```sequence
Client->Server: Client Auth [0x08]
Server->Client: Server Auth [0x09]
Client->Server: Transport Data [0x10]
Server->Client: Transport Data [0x10]
```
#### Hop Noise PQ IK Pattern

---

```sequence
<- skem
...
-> ekem, Encaps(skem), Encrypt(certs (s))
<- Encaps(ekem), Encrypt(certs (s)) // DH (ss)
```


### Message Structures


##### Client Request Message

---

|      type $:=$ 0x18 (1 byte)      |          Protocol Version (1 byte)          |       Certs Len $:= 0^2$ (2 bytes)        |
|:---------------------------------:|:-------------------------------------------:|:-----------------------------------------:|
|                                   |    Client  Ephemeral ML-KEM (800 bytes)     |                                           |
|                                   |         Client sKEM CT (768 bytes)          |                                           |
| Client Leaf Certificate (* bytes) |                                             | Client Intermediate Certificate (* bytes) |
|                                   | Client Static Authentication Tag (16 bytes) |                                           |
|                                   |             Timestamp (8 bytes)             |                                           |
|                                   |               MAC (16 bytes)                |                                           |

##### Client Request Construction

---

```python
# server’s static key is cached from a previous discoverable mode handshake, or distributed out-of-band
protocolID = “hop_pqIK_cyclist_keccak_C512”
duplex = Cyclist()
duplex.absorb(protocolID)
duplex.absorb([type + protocol + reserved])
duplex.absorb(ekem_c)
ct, k = kem.Encaps(skem_s) #skem
duplex.absorb(k)
ClientEncCerts = duplex.encrypt(certificates)
tag = duplex.squeeze()
timestamp = duplex.encrypt(time.Now().Unix())
mac = duplex.squeeze()
```

##### Server Logic

---

```python
protocolID = “hop_pqIK_cyclist_keccak_C512”
for vmCert in certList:
  duplex = Cyclist()
  duplex.absorb(protocolID)
  duplex.absorb([type + protocol + reserved])
  duplex.absorb(ekem_c)
  k = vmCert.skem_s.Decaps(ct) # skem
  duplex.absorb(k)
  certificates = duplex.decrypt(ClientEncCerts)
  tag = duplex.squeeze()
  # verify tag if equal break

# verify certs, extract client static
timestamp = duplex.decrypt(time.Now().Unix())
mac = duplex.squeeze()
```

#### Server Auth Message

---


|      type $:=$ 0x8 (1 byte)       |       Reserved $:= 0$ (1 byte)       |       Certs Len $:= 0^2$ (2 bytes)        |
|:---------------------------------:|:------------------------------------:|:-----------------------------------------:|
|                                   |         SessionID (4 bytes)          |                                           |
|                                   |      Server eKEM CT (768 bytes)      |                                           |
| Server Leaf Certificate (* bytes) |                                      | Server Intermediate Certificate (* bytes) |
|                                   | Server Authentication Tag (16 bytes) |                                           |
|                                   |            MAC (16 bytes)            |                                           |


##### Server Auth Construction

---

```python
# Continuing from duplex prior
duplex.absorb([type + reserved + Certs Len])
duplex.absorb(SessionID)
ct, k = kem.Encpaps(ekem_c) #ekem
duplex.absorb(k)
ServerEncCerts = duplex.encrypt(certificates)
tag = duplex.squeeze()
duplex.absorb(DH(ss))
mac = duplex.squeeze()
```

##### Client Logic

---

```python
# Continuing from duplex prior
duplex.absorb([type + reserved + Certs Len])
duplex.absorb(SessionID)
e = ekem_c.Dec(ct) # ekem
duplex.absorb(k)
certificates = duplex.decrypt(ServerEncCerts)
tag = duplex.squeeze()
# verify tag
# verify certs, extract server static
duplex.absorb(DH(ss))
mac = duplex.squeeze()
```

### Transport Message

#### Client & Server Key Derivation

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

#### Message

---

|  type $:=$ 0x6 (1 byte)  | reserved $:= 0^3$ (3 bytes) |
| :----------------------: | :-------------------------: |
|   SessionID (4 bytes)    |      Counter (8 bytes)      |
| Encrypted Data (* bytes) |                             |

Counter is a literal counter. Is not a nonce.

Encrypted data will contain a nonce at the front, if necessary, and a Mac. The AEAD implementation should verify the mac as part of the open/seal.

#### Transport Construction

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
