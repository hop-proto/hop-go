FROM golang:1.23

WORKDIR /app

# Download dependencies. Doing it here means we don't neet
# to download them again whenever we rebuild the image
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy go code into the image and build it
COPY . .
RUN go build hop.computer/hop/cmd/hopd
