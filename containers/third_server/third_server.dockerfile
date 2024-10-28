FROM golang:1.23

RUN mkdir -p /etc/hopd
COPY ./CAFiles/root.cert /etc/hopd/root.cert
COPY ./CAFiles/intermediate.cert /etc/hopd/intermediate.cert
COPY ./third_server/id_server.pem /etc/hopd/id_hop.pem
RUN chmod 600 /etc/hopd/id_hop.pem

COPY ./third_server/id_server.pub /etc/hopd/id_hop.pub
COPY ./third_server/id_server.cert /etc/hopd/id_hop.cert
COPY ./third_server/third_server_config /etc/hopd/config

# using certs for authentication, but authorized keys for user authorization
# still
COPY ./principal_client/id_client.pub /root/.hop/authorized_keys

COPY ./hop /root/hop
COPY ./CAFiles/root.cert /root/.hop/root.cert
COPY ./CAFiles/intermediate.cert /root/.hop/intermediate.cert

WORKDIR /app
CMD ./containers/hopd-wrapper.sh
