#!/usr/bin/env bash
set -e
set -o pipefail

HOP_DIR=${PWD}

echo ${HOP_DIR}
mkdir -p ${HOP_DIR}/containers/CAFiles

# Generate CAFiles used to sign other certificates and such
CA_CERT_DNS_NAME=${CA_CERT_DNS_NAME:='super_ca.com'}
CAFILES_OUTPUT_DIR=${HOP_DIR}/${CAFILES_OUTPUT_DIR:='./containers/CAFiles'}

# Variables for Hop commands
HOP_GEN="go run ${HOP_DIR}/cmd/hop-gen"
HOP_ISSUE="go run ${HOP_DIR}/cmd/hop-issue"

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

## client
EX_CLIENT_CERT_DNS_NAME=${EX_CLIENT_CERT_DNS_NAME:='root'}
EX_CLIENT_CERT_OUTPUT_DIR=${HOP_DIR}/${EX_CLIENT_CERT_OUTPUT_DIR:='./containers'}

## private keys
${HOP_GEN} | tee $EXAMPLE_CERT_OUTPUT_DIR/id_server.pem
${HOP_GEN} | tee $EX_CLIENT_CERT_OUTPUT_DIR/id_client.pem

## public keys
${HOP_GEN} -private $EXAMPLE_CERT_OUTPUT_DIR/id_server.pem | tee $EXAMPLE_CERT_OUTPUT_DIR/id_server.pub
${HOP_GEN} -private $EX_CLIENT_CERT_OUTPUT_DIR/id_client.pem | tee $EX_CLIENT_CERT_OUTPUT_DIR/id_client.pub

## certs
${HOP_ISSUE} -type leaf -key-file $CAFILES_OUTPUT_DIR/intermediate-key.pem -cert-file $CAFILES_OUTPUT_DIR/intermediate.cert -public-key $EXAMPLE_CERT_OUTPUT_DIR/id_server.pub -dns-name $EXAMPLE_CERT_DNS_NAME | tee $EXAMPLE_CERT_OUTPUT_DIR/id_server.cert
${HOP_ISSUE} -type leaf -key-file $CAFILES_OUTPUT_DIR/intermediate-key.pem -cert-file $CAFILES_OUTPUT_DIR/intermediate.cert -public-key $EX_CLIENT_CERT_OUTPUT_DIR/id_client.pub -dns-name $EX_CLIENT_CERT_DNS_NAME | tee $EX_CLIENT_CERT_OUTPUT_DIR/id_client.cert


# Authgrant tests (authgrant-dev and authgrant-chain-dev) setup
## servers
TARGET_CERT_DNS_NAME=${TARGET_CERT_DNS_NAME:='target.com'}
DELEGATE_CERT_DNS_NAME=${DELEGATE_CERT_DNS_NAME:='delegate.com'}
THIRD_CERT_DNS_NAME=${THIRD_CERT_DNS_NAME:='third.com'}

TARGET_CERT_OUTPUT_DIR=${HOP_DIR}/${TARGET_CERT_OUTPUT_DIR:='./containers/target_server'}
DELEGATE_CERT_OUTPUT_DIR=${HOP_DIR}/${DELEGATE_CERT_OUTPUT_DIR:='./containers/delegate_proxy_server'}
THIRD_CERT_OUTPUT_DIR=${HOP_DIR}/${THIRD_CERT_OUTPUT_DIR:='./containers/third_server'}

## client
PRINCIPAL_CERT_DNS_NAME=${PRINCIPAL_CERT_DNS_NAME:='principal'}
PRINCIPAL_CERT_OUTPUT_DIR=${HOP_DIR}/${PRINCIPAL_CERT_OUTPUT_DIR:='./containers/principal_client'}

## Private Keys
${HOP_GEN} | tee $TARGET_CERT_OUTPUT_DIR/id_server.pem
${HOP_GEN} | tee $DELEGATE_CERT_OUTPUT_DIR/id_server.pem
${HOP_GEN} | tee $THIRD_CERT_OUTPUT_DIR/id_server.pem

${HOP_GEN} | tee $PRINCIPAL_CERT_OUTPUT_DIR/id_client.pem

## Public Keys
${HOP_GEN} -private $TARGET_CERT_OUTPUT_DIR/id_server.pem | tee $TARGET_CERT_OUTPUT_DIR/id_server.pub
${HOP_GEN} -private $DELEGATE_CERT_OUTPUT_DIR/id_server.pem | tee $DELEGATE_CERT_OUTPUT_DIR/id_server.pub
${HOP_GEN} -private $THIRD_CERT_OUTPUT_DIR/id_server.pem | tee $THIRD_CERT_OUTPUT_DIR/id_server.pub

${HOP_GEN} -private $PRINCIPAL_CERT_OUTPUT_DIR/id_client.pem | tee $PRINCIPAL_CERT_OUTPUT_DIR/id_client.pub

## Certs
${HOP_ISSUE} -type leaf -key-file $CAFILES_OUTPUT_DIR/intermediate-key.pem -cert-file $CAFILES_OUTPUT_DIR/intermediate.cert -public-key $TARGET_CERT_OUTPUT_DIR/id_server.pub -dns-name $TARGET_CERT_DNS_NAME | tee $TARGET_CERT_OUTPUT_DIR/id_server.cert
${HOP_ISSUE} -type leaf -key-file $CAFILES_OUTPUT_DIR/intermediate-key.pem -cert-file $CAFILES_OUTPUT_DIR/intermediate.cert -public-key $DELEGATE_CERT_OUTPUT_DIR/id_server.pub -dns-name $DELEGATE_CERT_DNS_NAME | tee $DELEGATE_CERT_OUTPUT_DIR/id_server.cert
${HOP_ISSUE} -type leaf -key-file $CAFILES_OUTPUT_DIR/intermediate-key.pem -cert-file $CAFILES_OUTPUT_DIR/intermediate.cert -public-key $THIRD_CERT_OUTPUT_DIR/id_server.pub -dns-name $THIRD_CERT_DNS_NAME | tee $THIRD_CERT_OUTPUT_DIR/id_server.cert

${HOP_ISSUE} -type leaf -key-file $CAFILES_OUTPUT_DIR/intermediate-key.pem -cert-file $CAFILES_OUTPUT_DIR/intermediate.cert -public-key $PRINCIPAL_CERT_OUTPUT_DIR/id_client.pub -dns-name $PRINCIPAL_CERT_DNS_NAME | tee $PRINCIPAL_CERT_OUTPUT_DIR/id_client.cert
