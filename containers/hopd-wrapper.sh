#!/usr/bin/env bash
set -e

go install ./cmd/hcp

mkdir -p /etc/hopd
go run ./cmd/hopd -V -C /etc/hopd/config
