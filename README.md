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
$ go run ./cmd/hop -C ./containers/client_config root@127.0.0.1:7777
```
