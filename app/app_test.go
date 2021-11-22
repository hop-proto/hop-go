package app

import "testing"

func TestClientServerInterop(t *testing.T) {
	server = Server()
	client = Client()

	client.Handshake(server.URL)
}
