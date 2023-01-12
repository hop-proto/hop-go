FROM golang:1.19

RUN mkdir -p /etc/hopd
COPY ./delegate_proxy_server/id_server.pem /etc/hopd/id_hop.pem
RUN chmod 600 /etc/hopd/id_hop.pem
COPY ./delegate_proxy_server/id_server.pub /etc/hopd/id_hop.pub
COPY ./delegate_proxy_server/id_server.cert /etc/hopd/id_hop.cert
COPY ./delegate_proxy_server/delegate_proxy_server_config /etc/hopd/config

COPY ./principal_client/id_client.pub /root/.hop/authorized_keys

COPY ./delegate_proxy_server/hop /root/hop
COPY ./delegate_client/delegate_config /root/.hop/config

WORKDIR /app
CMD ./containers/hopd-wrapper.sh
