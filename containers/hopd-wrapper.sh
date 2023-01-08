#!/usr/bin/env bash
set -e

mkdir -p /etc/hopd
apt update
apt install net-tools
go run ./cmd/hopd -V -C /etc/hopd/config

