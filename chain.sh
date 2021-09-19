#!/usr/bin/env bash
set -e
set -o pipefail

HOP_CERT_DNS_NAME=${HOP_CERT_DNS_NAME:='domain.example'}
HOP_CERT_OUTPUT_DIR=${HOP_CERT_OUTPUT_DIR:='.'}

# Private Keys
go run ./cmd/hop-gen -signing | tee $HOP_CERT_OUTPUT_DIR/root-key.pem
go run ./cmd/hop-gen -signing | tee $HOP_CERT_OUTPUT_DIR/intermediate-key.pem
go run ./cmd/hop-gen | tee $HOP_CERT_OUTPUT_DIR/leaf-key.pem

# Public Keys
go run ./cmd/hop-gen -signing -private $HOP_CERT_OUTPUT_DIR/root-key.pem | tee $HOP_CERT_OUTPUT_DIR/root.pub
go run ./cmd/hop-gen -signing -private $HOP_CERT_OUTPUT_DIR/intermediate-key.pem | tee $HOP_CERT_OUTPUT_DIR/intermediate.pub
go run ./cmd/hop-gen -private $HOP_CERT_OUTPUT_DIR/leaf-key.pem | tee $HOP_CERT_OUTPUT_DIR/leaf.pub

# Certs
go run ./cmd/hop-issue -type root -key-file $HOP_CERT_OUTPUT_DIR/root-key.pem -dns-name $HOP_CERT_DNS_NAME | tee $HOP_CERT_OUTPUT_DIR/root.pem
go run ./cmd/hop-issue -type intermediate -key-file $HOP_CERT_OUTPUT_DIR/root-key.pem -cert-file $HOP_CERT_OUTPUT_DIR/root.pem -public-key $HOP_CERT_OUTPUT_DIR/intermediate.pub -dns-name $HOP_CERT_DNS_NAME | tee $HOP_CERT_OUTPUT_DIR/intermediate.pem
go run ./cmd/hop-issue -type leaf -key-file $HOP_CERT_OUTPUT_DIR/intermediate-key.pem -cert-file $HOP_CERT_OUTPUT_DIR/intermediate.pem -public-key $HOP_CERT_OUTPUT_DIR/leaf.pub -dns-name $HOP_CERT_DNS_NAME | tee $HOP_CERT_OUTPUT_DIR/leaf.pem
