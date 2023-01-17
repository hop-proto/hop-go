FROM golang:1.19

RUN mkdir -p /etc/hopd
COPY ./target_server/id_server.pem /etc/hopd/id_hop.pem
RUN chmod 600 /etc/hopd/id_hop.pem
COPY ./target_server/id_server.pub /etc/hopd/id_hop.pub
COPY ./target_server/id_server.cert /etc/hopd/id_hop.cert
COPY ./target_server/target_server_config /etc/hopd/config

COPY ./principal_client/id_client.pub /root/.hop/authorized_keys

WORKDIR /app
CMD ./containers/hopd-wrapper.sh
