#!/usr/bin/env bash
set -e
set -o pipefail

HOME=${PWD}/../

CA_CERT_DNS_NAME=${CA_CERT_DNS_NAME:='super_ca.com'}
CAFILES_OUTPUT_DIR=${HOME}${CAFILES_OUTPUT_DIR:='./containers/CAFiles'}

# servers
TARGET_CERT_DNS_NAME=${TARGET_CERT_DNS_NAME:='target.com'}
DELEGATE_CERT_DNS_NAME=${DELEGATE_CERT_DNS_NAME:='delegate.com'}
THIRD_CERT_DNS_NAME=${THIRD_CERT_DNS_NAME:='third.com'}

TARGET_CERT_OUTPUT_DIR=${HOME}${TARGET_CERT_OUTPUT_DIR:='./containers/target_server'}
DELEGATE_CERT_OUTPUT_DIR=${HOME}${DELEGATE_CERT_OUTPUT_DIR:='./containers/delegate_proxy_server'}
THIRD_CERT_OUTPUT_DIR=${HOME}${THIRD_CERT_OUTPUT_DIR:='./containers/third_server'}

# client
PRINCIPAL_CERT_DNS_NAME=${PRINCIPAL_CERT_DNS_NAME:='principal'}
PRINCIPAL_CERT_OUTPUT_DIR=${HOME}${PRINCIPAL_CERT_OUTPUT_DIR:='./containers/principal_client'}

# Private Keys
go run ${HOME}/cmd/hop-gen -signing | tee $CAFILES_OUTPUT_DIR/root-key.pem
go run ${HOME}/cmd/hop-gen -signing | tee $CAFILES_OUTPUT_DIR/intermediate-key.pem

go run ${HOME}/cmd/hop-gen | tee $TARGET_CERT_OUTPUT_DIR/id_server.pem
go run ${HOME}/cmd/hop-gen | tee $DELEGATE_CERT_OUTPUT_DIR/id_server.pem
go run ${HOME}/cmd/hop-gen | tee $THIRD_CERT_OUTPUT_DIR/id_server.pem

go run ${HOME}/cmd/hop-gen | tee $PRINCIPAL_CERT_OUTPUT_DIR/id_client.pem

# Public Keys
go run ${HOME}/cmd/hop-gen -signing -private $CAFILES_OUTPUT_DIR/root-key.pem | tee $CAFILES_OUTPUT_DIR/root.pub
go run ${HOME}/cmd/hop-gen -signing -private $CAFILES_OUTPUT_DIR/intermediate-key.pem | tee $CAFILES_OUTPUT_DIR/intermediate.pub

go run ${HOME}/cmd/hop-gen -private $TARGET_CERT_OUTPUT_DIR/id_server.pem | tee $TARGET_CERT_OUTPUT_DIR/id_server.pub
go run ${HOME}/cmd/hop-gen -private $DELEGATE_CERT_OUTPUT_DIR/id_server.pem | tee $DELEGATE_CERT_OUTPUT_DIR/id_server.pub
go run ${HOME}/cmd/hop-gen -private $THIRD_CERT_OUTPUT_DIR/id_server.pem | tee $THIRD_CERT_OUTPUT_DIR/id_server.pub

go run ${HOME}/cmd/hop-gen -private $PRINCIPAL_CERT_OUTPUT_DIR/id_client.pem | tee $PRINCIPAL_CERT_OUTPUT_DIR/id_client.pub

# Certs
go run ${HOME}/cmd/hop-issue -type root -key-file $CAFILES_OUTPUT_DIR/root-key.pem -dns-name $CA_CERT_DNS_NAME | tee $CAFILES_OUTPUT_DIR/root.cert
go run ${HOME}/cmd/hop-issue -type intermediate -key-file $CAFILES_OUTPUT_DIR/root-key.pem -cert-file $CAFILES_OUTPUT_DIR/root.cert -public-key $CAFILES_OUTPUT_DIR/intermediate.pub -dns-name $CA_CERT_DNS_NAME | tee $CAFILES_OUTPUT_DIR/intermediate.cert

go run ${HOME}/cmd/hop-issue -type leaf -key-file $CAFILES_OUTPUT_DIR/intermediate-key.pem -cert-file $CAFILES_OUTPUT_DIR/intermediate.cert -public-key $TARGET_CERT_OUTPUT_DIR/id_server.pub -dns-name $TARGET_CERT_DNS_NAME | tee $TARGET_CERT_OUTPUT_DIR/id_server.cert
go run ${HOME}/cmd/hop-issue -type leaf -key-file $CAFILES_OUTPUT_DIR/intermediate-key.pem -cert-file $CAFILES_OUTPUT_DIR/intermediate.cert -public-key $DELEGATE_CERT_OUTPUT_DIR/id_server.pub -dns-name $DELEGATE_CERT_DNS_NAME | tee $DELEGATE_CERT_OUTPUT_DIR/id_server.cert
go run ${HOME}/cmd/hop-issue -type leaf -key-file $CAFILES_OUTPUT_DIR/intermediate-key.pem -cert-file $CAFILES_OUTPUT_DIR/intermediate.cert -public-key $THIRD_CERT_OUTPUT_DIR/id_server.pub -dns-name $THIRD_CERT_DNS_NAME | tee $THIRD_CERT_OUTPUT_DIR/id_server.cert

go run ${HOME}/cmd/hop-issue -type leaf -key-file $CAFILES_OUTPUT_DIR/intermediate-key.pem -cert-file $CAFILES_OUTPUT_DIR/intermediate.cert -public-key $PRINCIPAL_CERT_OUTPUT_DIR/id_client.pub -dns-name $PRINCIPAL_CERT_DNS_NAME | tee $PRINCIPAL_CERT_OUTPUT_DIR/id_client.cert
