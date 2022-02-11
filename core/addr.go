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

// URL contains enough information to dial Hop server as a user
type URL struct {
	User string
	Host string
	Port string
}

// URL converts a Hop URL into a url.URL.
func (a URL) URL() url.URL {
	return url.URL{
		Scheme: "hop",
		Host:   a.Address(),
		User:   url.User(a.User),
	}
}

// String returns a URL of the form hop://[user@]host[:port].
func (a URL) String() string {
	u := a.URL()
	return u.String()
}

// Address return a string of the form "host:port".
func (a URL) Address() string {
	if a.Port != "" {
		return net.JoinHostPort(a.Host, a.Port)
	}
	return a.Host
}

// parseURL parses a URL of the form [hop://][user@]host[:port] to a url.URL. It
// will reject anything with a path, password, or fragment.
func parseURL(address string) (*url.URL, error) {
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

// ParseURL parses a Hop address of the form [hop://][user@]host[:port]
// into an Address.
func ParseURL(in string) (*URL, error) {
	u, err := parseURL(in)
	if err != nil {
		return nil, err
	}
	return &URL{
		Host: u.Hostname(),
		Port: u.Port(),
		User: u.User.Username(),
	}, nil
}

// MergeURLs takes an Address from a HostConfig, and an address from
// UserInput, and combines them according to the override rules.
//
// A non-empty value from the CLI will override the user or port. A non-empty
// Host from the config will override the CLI.
func MergeURLs(fromConfig, fromInput URL) URL {
	var out URL
	out.Host = combinators.StringOr(fromConfig.Host, fromInput.Host)
	out.Port = combinators.StringOr(fromInput.Port, fromConfig.Port)
	out.User = combinators.StringOr(fromInput.User, fromConfig.User)
	return out
}
