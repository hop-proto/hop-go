FROM golang:1.23

WORKDIR /

WORKDIR /app

RUN apt-get update -y
RUN apt-get install -y sudo

# Download dependencies. Doing it here means we don't neet
# to download them again whenever we rebuild the image
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy go code into the image and build it
COPY . .
RUN go build -tags debug -o /bin/hopd hop.computer/hop/cmd/hopd
RUN go build -o /bin/hop hop.computer/hop/cmd/hop
RUN go build -o /bin/acme-server hop.computer/hop/cmd/acme-server

# Set up users
RUN useradd -m acme -s /bin/bash -g sudo -p "" 
RUN useradd -m acme_server -s /bin/acme-server -p ""
RUN mkdir -p /home/acme_server/.hop
RUN echo '*' >> /home/acme_server/.hop/authorized_keys

COPY acme/acme_root /

CMD ["hopd", "-V"]
