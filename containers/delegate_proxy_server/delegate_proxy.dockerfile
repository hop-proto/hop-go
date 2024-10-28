FROM golang:1.23

RUN mkdir -p /etc/hopd
COPY ./CAFiles/root.cert /etc/hopd/root.cert
COPY ./CAFiles/intermediate.cert /etc/hopd/intermediate.cert
COPY ./delegate_proxy_server/id_server.pem /etc/hopd/id_hop.pem
RUN chmod 600 /etc/hopd/id_hop.pem
COPY ./delegate_proxy_server/id_server.pub /etc/hopd/id_hop.pub
COPY ./delegate_proxy_server/id_server.cert /etc/hopd/id_hop.cert
COPY ./delegate_proxy_server/delegate_proxy_server_config /etc/hopd/config

COPY ./hop /root/hop
COPY ./delegate_client/delegate_config /root/.hop/config
COPY ./CAFiles/root.cert /root/.hop/root.cert
COPY ./CAFiles/intermediate.cert /root/.hop/intermediate.cert

# using certs for authentication, but authorized keys for user authorization
# still
COPY ./principal_client/id_client.pub /root/.hop/authorized_keys

WORKDIR /app
CMD ./containers/hopd-wrapper.sh
