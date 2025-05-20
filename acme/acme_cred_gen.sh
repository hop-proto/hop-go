#!/usr/bin/env bash
set -exu
set -o pipefail

# Pass the name of your CA as the `CA_CERT_DNS_NAME` env variable

HOP_DIR=${PWD}

ACME_DIR="${HOP_DIR}/acme"
CAFILES_OUTPUT_DIR=${ACME_DIR}/${CAFILES_OUTPUT_DIR:="${ACME_DIR}/acme_root/etc/hopd/CAFiles"}

CA_CERT_OUTPUT_DIR="${}"

echo ${ACME_DIR}
mkdir -p ${CAFILES_OUTPUT_DIR}

# Generate CAFiles used to sign other certificates and such
CA_CERT_DNS_NAME=${CA_CERT_DNS_NAME:='super_ca.com'}

HOP_GEN=${HOP_GEN:='./hop-gen'}
HOP_ISSUE=${HOP_ISSUE:='./hop-issue'}

# Build Hop commands
go build -o ${HOP_GEN} "${HOP_DIR}/cmd/hop-gen"
go build -o ${HOP_ISSUE} "${HOP_DIR}/cmd/hop-issue"

## CA private keygen
${HOP_GEN} -signing | tee $CAFILES_OUTPUT_DIR/root-key.pem
${HOP_GEN} -signing | tee $CAFILES_OUTPUT_DIR/intermediate-key.pem

## CA public keygen
${HOP_GEN} -signing -private $CAFILES_OUTPUT_DIR/root-key.pem | tee $CAFILES_OUTPUT_DIR/root.pub
${HOP_GEN} -signing -private $CAFILES_OUTPUT_DIR/intermediate-key.pem | tee $CAFILES_OUTPUT_DIR/intermediate.pub

## CA cert gen
${HOP_ISSUE} -type root -key-file $CAFILES_OUTPUT_DIR/root-key.pem -dns-name $CA_CERT_DNS_NAME | tee $CAFILES_OUTPUT_DIR/root.cert
${HOP_ISSUE} -type intermediate -key-file $CAFILES_OUTPUT_DIR/root-key.pem -cert-file $CAFILES_OUTPUT_DIR/root.cert -public-key $CAFILES_OUTPUT_DIR/intermediate.pub -dns-name $CA_CERT_DNS_NAME | tee $CAFILES_OUTPUT_DIR/intermediate.cert
                   

# Generate files for make serve-dev (simple hop connection)
## server
EXAMPLE_CERT_DNS_NAME=${EXAMPLE_CERT_DNS_NAME:='example.com'}
EXAMPLE_CERT_OUTPUT_DIR=${HOP_DIR}/${EXAMPLE_CERT_OUTPUT_DIR:='./containers'}

## private keys
${HOP_GEN} | tee $CA_CERT_OUTPUT_DIR/id_server.pem

## public keys
${HOP_GEN} -private $CA_CERT_OUTPUT_DIR/id_server.pem | tee $EXAMPLE_CERT_OUTPUT_DIR/id_server.pub

## certs
${HOP_ISSUE} -type leaf -key-file $CAFILES_OUTPUT_DIR/intermediate-key.pem -cert-file $CAFILES_OUTPUT_DIR/intermediate.cert -public-key $EXAMPLE_CERT_OUTPUT_DIR/id_server.pub -dns-name $EXAMPLE_CERT_DNS_NAME | tee $EXAMPLE_CERT_OUTPUT_DIR/id_server.cert
