FROM golang:1.17

RUN mkdir -p /etc/hopd
COPY ./server_dev_config /etc/hopd/config

WORKDIR /app
CMD ./containers/hopd-wrapper.sh
