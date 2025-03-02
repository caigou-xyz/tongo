package wallet

import (
	"crypto/ed25519"

	"github.com/caigou-xyz/tongo/signer"

	"github.com/caigou-xyz/tongo/boc"
	"github.com/caigou-xyz/tongo/tlb"
	"github.com/caigou-xyz/tongo/ton"
)

type DataV3 struct {
	Seqno       uint32
	SubWalletId uint32
	PublicKey   tlb.Bits256
}

type walletV3 struct {
	version     Version
	publicKey   ed25519.PublicKey
	workchain   int
	subWalletID uint32
}

var _ wallet = &walletV3{}

func newWalletV3(ver Version, key ed25519.PublicKey, options Options) *walletV3 {
	workchain := defaultOr(options.Workchain, 0)
	subWalletID := defaultOr(options.SubWalletID, uint32(DefaultSubWallet+workchain))
	return &walletV3{
		version:     ver,
		publicKey:   key,
		workchain:   workchain,
		subWalletID: subWalletID,
	}
}

func (w *walletV3) generateAddress() (ton.AccountID, error) {
	stateInit, err := w.generateStateInit()
	if err != nil {
		return ton.AccountID{}, err
	}
	return generateAddress(w.workchain, *stateInit)
}

func (w *walletV3) generateStateInit() (*tlb.StateInit, error) {
	data := DataV3{
		Seqno:       0,
		SubWalletId: w.subWalletID,
		PublicKey:   publicKeyToBits(w.publicKey),
	}
	return generateStateInit(w.version, data)
}

func (w *walletV3) maxMessageNumber() int {
	return 4
}

func (w *walletV3) createSignedMsgBodyCell(signer signer.Signer, internalMessages []RawMessage, msgConfig MessageConfig) (*boc.Cell, error) {
	body := MessageV3{
		SubWalletId: w.subWalletID,
		ValidUntil:  uint32(msgConfig.ValidUntil.Unix()),
		Seqno:       msgConfig.Seqno,
		RawMessages: PayloadV1toV4(internalMessages),
	}
	bodyCell := boc.NewCell()
	if err := tlb.Marshal(bodyCell, body); err != nil {
		return nil, err
	}
	return signBodyCell(*bodyCell, signer)
}

func (w *walletV3) NextMessageParams(state tlb.ShardAccount) (NextMsgParams, error) {
	if state.Account.Status() == tlb.AccountActive {
		var data DataV3
		cell := boc.Cell(state.Account.Account.Storage.State.AccountActive.StateInit.Data.Value.Value)
		if err := tlb.Unmarshal(&cell, &data); err != nil {
			return NextMsgParams{}, err
		}
		return NextMsgParams{
			Seqno: data.Seqno,
		}, nil
	}
	init, err := w.generateStateInit()
	if err != nil {
		return NextMsgParams{}, err
	}
	return NextMsgParams{Init: init}, nil
}
