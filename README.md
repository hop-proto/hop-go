Hop
===

Hop is a transport and remote access protocol addressing many of SSH's shortcomings.

Among other functionalities, Hop proposes a cryptographically-mediated delegation scheme, native host identification based on lessons from TLS and ACME, client authentication for modern enterprise environments, and support for client roaming and intermittent connectivity.

A detailed description of Hop design and requirements can be found in our original [paper](https://paul.flammarion.eu/document/hop.pdf), which will appear at [USENIX Security '26](https://www.usenix.org/conference/usenixsecurity26).

# Architecture

See [ARCHITECTURE](./ARCHITECTURE.md) for details on how this project is structured.

# Quick Start

Set up `$GOPATH` (see https://go.dev/wiki/SettingGOPATH).

```
$ git clone https://github.com/hop-proto/hop-go.git
$ cd hop-go
$ go get ./...; go get -t ./...
```

#### Generating Keys

There are two different keygen tools at the moment. We know
this is not ideal, but we haven't sorted out a better interface (yet).


```cmd
$ go run ./cmd/hop-keygen --help  # Keygen, use for self-signed keys
$ go run ./cmd/hop-issue --help   # Use with hop-gen for cert chains
$ go run ./cmd/hop-gen --help     # A more complicated keygen
```


More about certificate generation and Hop configuration can be found in [CONFIGURATION](./CONFIGURATION.md)

#### Running Hop
```cmd
$ go run cmd/hopd -C ./hopd_config.toml # runs Hop server
$ go run cmd/hop -C ./hop_config.toml user@host:port  # runs Hop client
```

#### Local testing with Docker

This will build the server in a Docker container and run it.
```cmd
$ make cred-gen # To generate the default credentials
$ make serve-dev  # Build and launch a server container
$ docker ps  # Look for the container name, in case you need to stop it later.
$ go run ./cmd/hop -C ./containers/client_config.toml user@127.0.0.1
```

Success is having a shell as `user` in the Docker container `example.com`

>[!NOTE]
> If you have `io.Copy(tube, f) stopped with error: read /dev/ptmx: input/output error` restarting the container or downgrading Go to 1.23 fixes this issue.

# License and Copyright

Copyright 2025 The Board of Trustees of The Leland Stanford Junior University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Acknowledgements

Hop was supported in part by a Sloan Research Fellowship and the National Science Foundation under Grant Number #2319080.