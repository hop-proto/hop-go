FROM golang:1.19

RUN mkdir -p /etc/hopd
COPY server_a/id_server.pem /etc/hopd/id_hop.pem
RUN chmod 600 /etc/hopd/id_hop.pem
COPY server_a/id_server.pub /etc/hopd/id_hop.pub
COPY server_a/id_server.cert /etc/hopd/id_hop.cert
COPY server_a/server_dev_config /etc/hopd/config

COPY CA_a/root.cert /etc/hopd/root.cert
COPY CA_a/intermediate.cert /etc/hopd/intermediate.cert

COPY client_principal/id_client.pub /root/.hop/authorized_keys

COPY client_delegate/client_config /root/.hop/config
COPY client_delegate/hop /root/hop

WORKDIR /app
CMD ./containers/hopd-wrapper.sh
