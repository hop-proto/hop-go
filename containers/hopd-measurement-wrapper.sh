#!/usr/bin/env bash
set -e

/usr/sbin/sshd

mkdir -p /etc/hopd
go run ./cmd/hopd -V -C /etc/hopd/config
