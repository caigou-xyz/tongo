package tonconnect

import (
	"encoding/base64"
	"github.com/caigou-xyz/tongo/signer"
	"time"

	"github.com/caigou-xyz/tongo"
	"github.com/caigou-xyz/tongo/boc"
	"github.com/caigou-xyz/tongo/tlb"
)

// ProofOptions configures particular aspects of a proof.
type ProofOptions struct {
	Timestamp time.Time
	Domain    string
}

// CreateSignedProof returns a proof that the caller posses a private key of a particular account.
// This can be used on the client side,
// when the server side runs tonconnect.Server or any other server implementation of ton-connect.
func CreateSignedProof(payload string, accountID tongo.AccountID, signer signer.Signer, stateInit tlb.StateInit, options ProofOptions) (*Proof, error) {
	stateInitCell := boc.NewCell()
	if err := tlb.Marshal(stateInitCell, stateInit); err != nil {
		return nil, err
	}
	stateInitBase64, err := stateInitCell.ToBocBase64()
	if err != nil {
		return nil, err
	}
	proof := Proof{
		Address: accountID.String(),
		Proof: ProofData{
			Timestamp: options.Timestamp.Unix(),
			Domain:    options.Domain,
			Payload:   payload,
			StateInit: stateInitBase64,
		},
	}
	parsedMsg, err := convertTonProofMessage(&proof)
	if err != nil {
		return nil, err
	}
	msg, err := createMessage(parsedMsg)
	if err != nil {
		return nil, err
	}
	message, err := signMessage(signer, msg)
	if err != nil {
		return nil, err
	}
	proof.Proof.Signature = base64.StdEncoding.EncodeToString(message)
	return &proof, nil
}
