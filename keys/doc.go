// Package keys contains wrappers for X25519 and Ed25519 as used in Hop. It can
// read and write private keys from PEM files, and public keys from text files.
// The API is not as memory efficient as it could be.
//
// It defines two key types: DH and Signing. DH (Diffie-Hellman) corresponds to
// X25519 keys, and are used for secret key negotiation. SigningKeys correspond
// to Ed25519 keys, and are used for signatures in certificates.
package keys
