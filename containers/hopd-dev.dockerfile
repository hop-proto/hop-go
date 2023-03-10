FROM golang:1.19

RUN mkdir -p /etc/hopd

COPY ./CAFiles/root.cert /etc/hopd/root.cert
COPY ./CAFiles/intermediate.cert /etc/hopd/intermediate.cert

COPY id_server.pem /etc/hopd/id_hop.pem
RUN chmod 600 /etc/hopd/id_hop.pem
COPY id_server.pub /etc/hopd/id_hop.pub
COPY id_server.cert /etc/hopd/id_hop.cert
COPY ./server_dev_config /etc/hopd/config

COPY id_client.pub /root/.hop/authorized_keys

WORKDIR /app
CMD ./containers/hopd-wrapper.sh
