FROM golang:1.23

WORKDIR /
COPY acme/acme_root /

WORKDIR /app

RUN apt-get update -y
RUN apt-get install -y sudo

RUN useradd -m acme -s /bin/bash -g sudo -p "" 
RUN useradd -m acme_client -s /app/acme/request_cert.sh -p ""

# Download dependencies. Doing it here means we don't neet
# to download them again whenever we rebuild the image
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy go code into the image and build it
COPY . .
RUN go build -o /bin/hopd hop.computer/hop/cmd/hopd
RUN go build -o /bin/hop hop.computer/hop/cmd/hop

CMD ["hopd"]
