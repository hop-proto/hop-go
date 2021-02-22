package transport

type ClientConfig struct{}

type PacketCallback func(SessionID, []byte)

type ServerConfig struct {
	OnReceive PacketCallback
}
