This directory contains files used when building production and test containers
for Hop, including test keys, Docker files, entrypoints, etc.

# Running one server
Run the following commands from the `hop-go` directory
  - `make serve-dev` to launch the docker image
  - `go run hop.computer/hop/cmd/hop -C containers/client_config.toml user@127.0.0.1:7777`
  to connect to the server

# Running one server with Hidden Handshake
Run the following commands from the `hop-go` directory
- `make serve-dev-hidden` to launch the docker image
- `go run hop.computer/hop/cmd/hop -C containers/hidden_server/client_config_hidden.toml user@127.0.0.1:5555`
  to connect to the server

# Running two servers
Run the following commands from the `hop-go` directory
  - `make authgrant-dev` to start the two servers
  - `go run hop.computer/hop/cmd/hop -C containers/principal_client/principal_config.toml user@127.0.0.1:8888`
  to connect to the delegate server
  - `hop user@target.com` to connect to the target

# Running three servers
Run the following commands from the `hop-go` directory
  - `make authgrant-chain-dev` to start all three servers
  - `go run hop.computer/hop/cmd/hop -C containers/principal_client/principal_config.toml user@127.0.0.1:8888`
  to connect to the delegate server
  - `hop user@target.com` to connect to the target
  - `hop user@third.com` to connect to the third server

While `hop`ed into any server, you can run `hostname` to see which server you're in

# Stopping the servers
Run `make stop-servers` to stop all docker instances

# Other commands
Run `docker-compose -f ./containers/docker-compose.yml` to see other useful docker commands
