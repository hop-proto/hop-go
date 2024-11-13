package core

import (
	"bufio"
	"bytes"
	"fmt"
	"hop.computer/hop/keys"
	"io"
	"net"
	"os"
	"strings"
)

type KnownHost struct {
	Address   *addr
	PublicKey *keys.PublicKey
}

type KnownHosts []KnownHost

// The Read function parses file contents.
func ParseKnownHosts(r io.Reader) (KnownHosts, error) {
	scanner := bufio.NewScanner(r)
	var khosts KnownHosts

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		address, key, err := parseLine(line)
		khosts = append(khosts, KnownHost{Address: address, PublicKey: key})

		if err != nil {
			return nil, fmt.Errorf("knownhosts: %v: %v", lineNum, err)
		}
	}
	return khosts, scanner.Err()
}

func ParseKnownHostFile(path string) (KnownHosts, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return ParseKnownHosts(r)
}

// Line returns a line to add append to the known_hosts files.
func Line(addresses []string, key keys.PublicKey) string {
	var trimmed []string
	for _, a := range addresses {
		trimmed = append(trimmed, Normalize(a))
	}

	return strings.Join(trimmed, ",") + " " + key.String()
}

type addr struct{ host, port string }

func (a *addr) String() string {
	h := a.host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return h + ":" + a.port
}

func nextWord(line []byte) (string, []byte) {
	i := bytes.IndexAny(line, "\t ")
	if i == -1 {
		return string(line), nil
	}

	return string(line[:i]), bytes.TrimSpace(line[i:])
}

func parseLine(line []byte) (address *addr, key *keys.PublicKey, err error) {
	hostString, line := nextWord(line)
	if len(line) == 0 {
		return nil, nil, fmt.Errorf("knownhosts: missing host pattern")
	}

	keyBlob, _ := nextWord(line)

	key, err = keys.ParseDHPublicKey(keyBlob)
	if err != nil {
		return nil, nil, err
	}

	host, port, err := net.SplitHostPort(hostString)
	if err != nil {
		host = hostString
		port = "22"
	}

	address = &addr{host: host, port: port}

	return address, key, nil
}

func Normalize(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		port = "22"
	}
	entry := host
	if port != "22" {
		entry = "[" + entry + "]:" + port
	} else if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		entry = "[" + entry + "]"
	}
	return entry
}

// KnownKey represents a key declared in a known_hosts file.
type KnownKey struct {
	Key      keys.PublicKey
	Filename string
	Line     int
}

func (k *KnownKey) String() string {
	return fmt.Sprintf("%s:%d: %s", k.Filename, k.Line, k.String())
}
