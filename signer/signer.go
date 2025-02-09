package signer

import "crypto/ed25519"

type Signer interface {
	Sign(data []byte) ([]byte, error)
	PublicKey() ed25519.PublicKey
}
