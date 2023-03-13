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
COPY ssh_id_ed25519.pub /root/.ssh/authorized_keys

RUN apt update
RUN apt install -y ssh
RUN mkdir -p /run/sshd

RUN apt install -y iproute2

WORKDIR /app
CMD ./containers/hopd-measurement-wrapper.sh
