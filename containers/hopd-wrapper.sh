#!/usr/bin/env bash
set -e

mkdir -p /etc/hopd
go run ./cmd/hop-keygen -directory /etc/hopd
go run ./cmd/hopd -C /etc/hopd/config -s /@hopauth

