FROM golang:1.23

WORKDIR /app

RUN apt-get update -y
RUN apt-get install -y delve

# Download dependencies. Doing it here means we don't neet
# to download them again whenever we rebuild the image
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy go code into the image and build it
COPY . .
RUN go build -o /bin/hopd -tags debug hop.computer/hop/cmd/hopd
RUN go build -o /bin/hop -tags debug hop.computer/hop/cmd/hop
