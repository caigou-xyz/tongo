package wallet

import "crypto/ed25519"

type PrivateKeySigner struct {
	privateKey ed25519.PrivateKey
}

func NewPrivateKeySigner(privateKey ed25519.PrivateKey) *PrivateKeySigner {
	return &PrivateKeySigner{
		privateKey: privateKey,
	}
}

func (s *PrivateKeySigner) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, data[:]), nil
}

func (s *PrivateKeySigner) PublicKey() (ed25519.PublicKey, error) {
	return s.privateKey.Public().(ed25519.PublicKey), nil
}
