package wallet

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"

	"github.com/caigou-xyz/aegis/client"
	"github.com/caigou-xyz/tongo/signer"
	"github.com/caigou-xyz/tongo/ton"
)

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

func (s *PrivateKeySigner) PublicKey() ed25519.PublicKey {
	return s.privateKey.Public().(ed25519.PublicKey)
}

type RemoteSigner struct {
	client    *client.Client
	accountId string
	publicKey ed25519.PublicKey
}

func NewRemoteSigner(client *client.Client, accountId string, publicKey ed25519.PublicKey) (signer.Signer, error) {
	_, err := ton.ParseAccountID(accountId)
	if err != nil {
		return nil, err
	}

	if publicKey == nil || len(publicKey) == 0 {
		account, err := client.GetTONAccount(context.Background(), accountId)
		if err != nil {
			return nil, err
		}
		publicKey, err = hex.DecodeString(strings.TrimPrefix(account.PublicKeyHex, "0x"))
		if err != nil {
			return nil, err
		}
	}

	return &RemoteSigner{
		client:    client,
		accountId: accountId,
		publicKey: publicKey,
	}, nil
}

func (s *RemoteSigner) Sign(data []byte) ([]byte, error) {
	return s.client.SignTON(context.Background(), s.accountId, data)
}

func (s *RemoteSigner) PublicKey() ed25519.PublicKey {
	return s.publicKey
}
