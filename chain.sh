#!/usr/bin/env bash
set -e
set -o pipefail

# Private Keys
go run ./cmd/hop-gen -signing | tee root-key.pem
go run ./cmd/hop-gen -signing | tee intermediate-key.pem
go run ./cmd/hop-gen | tee leaf-key.pem

# Public Keys
go run ./cmd/hop-gen -signing -private root-key.pem | tee root.pub
go run ./cmd/hop-gen -signing -private intermediate-key.pem | tee intermediate.pub
go run ./cmd/hop-gen -private leaf-key.pem | tee leaf.pub

# Certs
go run ./cmd/hop-issue -type root -key-file root-key.pem | tee root.pem
go run ./cmd/hop-issue -type intermediate -key-file root-key.pem -cert-file root.pem -public-key intermediate.pub | tee intermediate.pem
go run ./cmd/hop-issue -type leaf -key-file intermediate-key.pem -cert-file intermediate.pem -public-key leaf.pub | tee leaf.pem
