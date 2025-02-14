package wallet

import (
	"crypto/ed25519"
	"github.com/caigou-xyz/tongo/signer"
	"math/rand"

	"github.com/caigou-xyz/tongo/boc"
	"github.com/caigou-xyz/tongo/tlb"
	"github.com/caigou-xyz/tongo/ton"
)

// DataHighloadV2 represents data of a highload-wallet contract.
type DataHighloadV2 struct {
	SubWalletId     uint32
	LastCleanedTime uint64
	PublicKey       tlb.Bits256
	Queries         tlb.HashmapE[tlb.Uint64, tlb.Any]
}

type walletHighloadV2 struct {
	version     Version
	publicKey   ed25519.PublicKey
	workchain   int
	subWalletID uint32
}

var _ wallet = &walletHighloadV2{}

func newWalletHighloadV2(ver Version, key ed25519.PublicKey, options Options) *walletHighloadV2 {
	workchain := defaultOr(options.Workchain, 0)
	subWalletID := defaultOr(options.SubWalletID, uint32(DefaultSubWallet+workchain))
	return &walletHighloadV2{
		version:     ver,
		publicKey:   key,
		workchain:   workchain,
		subWalletID: subWalletID,
	}
}

func (w *walletHighloadV2) generateAddress() (ton.AccountID, error) {
	stateInit, err := w.generateStateInit()
	if err != nil {
		return ton.AccountID{}, err
	}
	return generateAddress(w.workchain, *stateInit)
}

func (w *walletHighloadV2) generateStateInit() (*tlb.StateInit, error) {
	data := DataHighloadV2{
		SubWalletId: w.subWalletID,
		PublicKey:   publicKeyToBits(w.publicKey),
	}
	return generateStateInit(w.version, data)
}

func (w *walletHighloadV2) maxMessageNumber() int {
	return 254
}

func (w *walletHighloadV2) createSignedMsgBodyCell(signer signer.Signer, internalMessages []RawMessage, msgConfig MessageConfig) (*boc.Cell, error) {
	boundedID := uint64(msgConfig.ValidUntil.UTC().Unix()<<32) + uint64(rand.Uint32())
	body := HighloadV2Message{
		SubWalletId:    w.subWalletID,
		BoundedQueryID: boundedID,
		RawMessages:    PayloadHighload(internalMessages),
	}
	bodyCell := boc.NewCell()
	if err := tlb.Marshal(bodyCell, body); err != nil {
		return nil, err
	}
	return signBodyCell(*bodyCell, signer)
}

func (w *walletHighloadV2) NextMessageParams(state tlb.ShardAccount) (NextMsgParams, error) {
	initRequired := state.Account.Status() == tlb.AccountUninit || state.Account.Status() == tlb.AccountNone
	if !initRequired {
		return NextMsgParams{}, nil
	}
	stateInit, err := w.generateStateInit()
	if err != nil {
		return NextMsgParams{}, err
	}
	return NextMsgParams{Init: stateInit}, nil
}
