# Hop – Keys, Certificates, and Configuration

This document describes how to generate keys and certificates for Hop and how to configure both server and client.


## Keys and Certificate Generation

Hop uses a simple PKI hierarchy:

- **Root**
- **Intermediate**
- **Leaf** (server and client)

Each level generates a key pair and issues a certificate signed by its parent.  
The **root**, **intermediate**, and **leaf** certificates can be generated on separate machines.


### Root Certificate

Generate a root signing key pair and issue a root certificate.

```sh
go run ./cmd/hop-keygen \
  -signing \
  -name root-key \
  -directory .
```
```sh
go run ./cmd/hop-issue \
  -type root \
  -key-file root-key.pem \
  > root.cert
```

The root private key is used only to sign intermediate certificates.

### Intermediate Certificate

Generate an intermediate signing key pair and issue an intermediate certificate signed by the root.

```sh
go run ./cmd/hop-keygen \
  -signing \
  -name intermediate-key \
  -directory .
```

```sh
go run ./cmd/hop-issue \
  -type intermediate \
  -key-file root-key.pem \
  -cert-file root.cert \
  -public-key intermediate-key.pub \
  -dns-name example.com \
  > intermediate.cert
```

The intermediate certificate is used to sign all leaf certificates.

### Leaf Certificate

Generate a leaf key pair and issue a leaf certificate signed by the intermediate.


```sh
go run ./cmd/hop-keygen \
  -name leaf-key \
  -directory .
```

```sh
go run ./cmd/hop-issue \
  -type leaf \
  -key-file intermediate-key.pem \
  -cert-file intermediate.cert \
  -public-key leaf-key.pub \
  -dns-name user \
  > leaf.cert
```

`dns-name`
The `dns-name` field is an identifier, not strictly a DNS record.

- **Server**: domain name or IP address
- **Client**: username or logical identifier

Both must appear in the client connection request:

```sh
hop user@host:port
```

> [!IMPORTANT]
> The server and client must use different leaf certificates.

### Hidden Mode

Generate the hidden mode key:

```shell
go run ./cmd/hop-keygen \
-kem \
-name kem-hop \
-directory .
```


This produces:
- `kem-hop.pem` (server private key)
- `kem-hop.pub` (client public key)

## Configuration File

### Server Configuration

```toml
ListenAddress = ":77"

Key = "./leaf.pem"
Certificate = "./leaf.cert"
CAFiles = ["./intermediate.cert", "./root.cert"]

KEMKey = "kem-hop.pem"
Users = ["root"]
HiddenModeVHostNames = ["127.0.0.1"]
```

- `Key` and `Certificate` reference the server leaf certificate
- `CAFiles` must include both the intermediate and root certificates
- `Users` is the set of user allowed on the server
- Hidden mode is enabled only when both `KEMKey` and `HiddenModeVHostNames` are set.


### Client Configuration

```toml
[Global]
Key = "./leaf.pem"
Certificate = "./leaf.cert"
CAFiles = ["./intermediate.cert", "./root.cert"]

[[Hosts]]
Patterns = ["127.0.0.1"]
ServerName = "127.0.0.1"
Port = 77
ServerKEMKeyPath = "./kem-hop.pub"
```

- `Key` and `Certificate` reference the client leaf certificate
- `CAFiles` must include both the intermediate and root certificates
- `ServerKEMKeyPath` is optional, but required when connecting to a server using hidden mode
