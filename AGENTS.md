# Contributor Guide

## Code Structure

See [ARCHITECTURE.md](./ARCHITECTURE.md) for more information about how the code
is structured, and what this repository does.

## Dev Environment Tips

- Use go test <relative_path_to_package> to test a single package instead of everything, e.g. `go test ./certs`
- Don't do anything that relies on Docker

## Testing Instructions

- Find the CI plan in the .github/workflows folder
- `make build` and `make test` should both pass
