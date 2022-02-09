// Package core contains Hop-specific library functions designed to be used by the Hop
// suite of tools.
package core

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"zmap.io/portal/pkg/combinators"
)

// Address contains enough information to dial Hop server
type Address struct {
	User string
	Host string
	Port string
}

// Network returns "hop"
func (a Address) Network() string {
	return "hop"
}

// String returns a URL of the form hop://[user@]host[:port].
func (a Address) String() string {
	u := url.URL{
		Host: net.JoinHostPort(a.Host, a.Port),
		User: url.User(a.User),
	}
	return u.String()
}

var _ net.Addr = Address{}

// ParseURL parses a URL of the form [hop://][user@]host[:port] to a url.URL. It
// will reject anything with a path, password, or fragment.
func ParseURL(address string) (*url.URL, error) {
	var u *url.URL
	var err error
	if strings.Contains(address, "://") {
		u, err = url.Parse(address)
	} else {
		// Force the URL to parse a scheme
		u, err = url.Parse(fmt.Sprintf("//%s", address))
	}
	if err != nil {
		return nil, err
	}

	if u.Path != "" || u.RawPath != "" {
		return nil, fmt.Errorf("hop URLs cannot contain a path: %q", u.String())
	}
	if u.RawQuery != "" {
		return nil, fmt.Errorf("hop URLs cannot contain a query: %q", u.String())
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return nil, fmt.Errorf("hop URLs cannot contain a query: %q", u.String())
	}

	if _, ok := u.User.Password(); ok {
		return nil, fmt.Errorf("input URL %s contains a password, only usernames are allowed", u.String())
	}
	return u, nil
}

// ParseAddress parses a Hop address of the form [hop://][user@]host[:port]
// into an Address.
func ParseAddress(address string) (*Address, error) {
	u, err := ParseURL(address)
	if err != nil {
		return nil, err
	}
	return &Address{
		Host: u.Hostname(),
		Port: u.Port(),
		User: u.User.Username(),
	}, nil
}

// MergeAddresses takes an Address from a HostConfig, and an address from
// UserInput, and combines them according to the override rules.
//
// A non-empty value from the CLI will override the user or port. A non-empty
// Host from the config will override the CLI.
func MergeAddresses(fromConfig, fromInput Address) Address {
	var out Address
	out.Host = combinators.StringOr(fromConfig.Host, fromInput.Host)
	out.Port = combinators.StringOr(fromConfig.Port, fromConfig.Port)
	out.User = combinators.StringOr(fromConfig.User, fromConfig.User)
	return out
}
