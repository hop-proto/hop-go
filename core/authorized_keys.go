package core

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"

	"zmap.io/portal/common"
	"zmap.io/portal/keys"
)

// AuthorizedKeys is a list of keys that can be used to authenticate as a single
// user.
type AuthorizedKeys []keys.PublicKey

// ParseAuthorizedKeys parses a list of DH public keys read from a reader.
func ParseAuthorizedKeys(r io.Reader) (authorized AuthorizedKeys, err error) {
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		k, err := keys.ParseDHPublicKey(line)
		if err != nil {
			return nil, err
		}
		authorized = append(authorized, *k)
	}
	return
}

// ParseAuthorizedKeysFile opens the file at path, and parses a list of DH public
// keys.
func ParseAuthorizedKeysFile(path string) (AuthorizedKeys, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return ParseAuthorizedKeys(r)
}

// AuthorizedKeysPath returns the path to a users authorized_keys file, given
// their user configuration directory.
func AuthorizedKeysPath(userDirectory string) string {
	return filepath.Join(userDirectory, common.AuthorizedKeysFile)
}

// Allowed returns true if the public key is in the authorized keys file.
func (akeys AuthorizedKeys) Allowed(pk keys.PublicKey) bool {
	for _, k := range akeys {
		if k == pk {
			return true
		}
	}
	return false
}
