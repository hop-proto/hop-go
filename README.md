Hop
===

See [ARCHITECTURE](./ARCHITECTURE.md) for details on how this project is
structured.

# Quickstart

Running Hop:
```cmd
$ go run cmd/hopd -C ./hopd_config # runs Hop server
$ go run cmd/hop -C ./hop_config user@host:port  # runs Hop client
```

**Generating Keys.** There are two different keygen tools at the moment. We know
this is not ideal, but we haven't sorted out a better interface (yet).
```cmd
$ go run ./cmd/hop-keygen --help  # Keygen, use for self-signed keys
$ go run ./cmd/hop-issue --help   # Use with hop-gen for cert chains
$ go run ./cmd/hop-gen --help     # A more complicated keygen
```

**Local testing with Docker.** It's annoying to test against your own home
directory, so this will build the server in a Docker container and run it. This
test harness code is very much WIP. For more info, see #38.
```cmd
$ make serve-dev  # Build and launch a server container
$ docker ps  # Look for the container name, in case you need to stop it later.
$ go run cmd/hop -C ./containers/client_config
```


## License and Copyright

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