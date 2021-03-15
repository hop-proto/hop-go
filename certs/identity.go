package certs

type IDType byte

const (
	DNSName   IDType = 0x01
	IPAddress IDType = 0x02
)

type Name struct {
	Label string
	Type  IDType
}

type Identity struct {
	PublicKey [KeyLen]byte
	Names     []Name
}

const (
	CanIdentify byte = 0
	CanSign     byte = 1
)

// NamesToBlocks converts the provided Names to IDBlocks, with the
// AuthorizationIndicator flag set to 0 (Identify)
func NamesToBlocks(names []Name) []IDBlock {
	out := make([]IDBlock, 0, len(names))
	for i := range names {
		out = append(out, IDBlock{
			Flags:    0xEF & byte(names[i].Type),
			ServerID: names[i].Label,
		})
	}
	return out
}
