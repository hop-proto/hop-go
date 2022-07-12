#!/usr/bin/env bash
set -e

mkdir -p /etc/hopd
go build ./cmd/hopd
./hopd -V -C /etc/hopd/config
