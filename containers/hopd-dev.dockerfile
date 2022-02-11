FROM golang:1.17

RUN mkdir -p /etc/hopd

WORKDIR /app
CMD ./containers/hopd-wrapper.sh
