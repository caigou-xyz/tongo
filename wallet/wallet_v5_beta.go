package wallet

import (
	"crypto/ed25519"
	"fmt"

	"github.com/caigou-xyz/tongo/signer"

	"github.com/caigou-xyz/tongo/boc"
	"github.com/caigou-xyz/tongo/tlb"
	"github.com/caigou-xyz/tongo/ton"
)

type WalletV5ID struct {
	NetworkGlobalID uint32
	Workchain       uint8
	WalletVersion   uint8
	SubWalletID     uint32
}

type DataV5Beta struct {
	Seqno      tlb.Uint33
	WalletID   WalletV5ID
	PublicKey  tlb.Bits256
	Extensions tlb.HashmapE[tlb.Bits256, tlb.Uint8]
}

type walletV5Beta struct {
	version         Version
	publicKey       ed25519.PublicKey
	workchain       int
	subWalletID     uint32
	networkGlobalID uint32
}

type V5MsgType uint32

const (
	V5MsgTypeSignedInternal  V5MsgType = 0x73696e74
	V5MsgTypeSignedExternal  V5MsgType = 0x7369676e
	V5MsgTypeExtensionAction V5MsgType = 0x6578746e
)

const TestnetGlobalID = -3
const MainnetGlobalID = -239

type MessageConfigV5 struct {
	MsgType V5MsgType
}

var _ wallet = &walletV5Beta{}

func NewWalletV5Beta(version Version, publicKey ed25519.PublicKey, opts Options) *walletV5Beta {
	workchain := defaultOr(opts.Workchain, 0)
	subWalletID := defaultOr(opts.SubWalletID, 0)

	networkGlobalID := defaultOr[int32](opts.NetworkGlobalID, MainnetGlobalID)
	return &walletV5Beta{
		version:         version,
		publicKey:       publicKey,
		workchain:       workchain,
		subWalletID:     subWalletID,
		networkGlobalID: uint32(networkGlobalID),
	}
}

func (w *walletV5Beta) generateAddress() (ton.AccountID, error) {
	stateInit, err := w.generateStateInit()
	if err != nil {
		return ton.AccountID{}, fmt.Errorf("can not generate state init: %v", err)
	}
	return generateAddress(w.workchain, *stateInit)
}

func (w *walletV5Beta) generateStateInit() (*tlb.StateInit, error) {
	data := DataV5Beta{
		Seqno: 0,
		WalletID: WalletV5ID{
			NetworkGlobalID: w.networkGlobalID,
			Workchain:       uint8(w.workchain),
			SubWalletID:     w.subWalletID,
		},
		PublicKey: publicKeyToBits(w.publicKey),
	}
	return generateStateInit(w.version, data)
}

func (w *walletV5Beta) maxMessageNumber() int {
	return 254
}

func (w *walletV5Beta) NextMessageParams(state tlb.ShardAccount) (NextMsgParams, error) {
	if state.Account.Status() == tlb.AccountActive {
		var data DataV5Beta
		cell := boc.Cell(state.Account.Account.Storage.State.AccountActive.StateInit.Data.Value.Value)
		if err := tlb.Unmarshal(&cell, &data); err != nil {
			return NextMsgParams{}, err
		}
		return NextMsgParams{
			Seqno: uint32(data.Seqno),
		}, nil
	}
	init, err := w.generateStateInit()
	if err != nil {
		return NextMsgParams{}, err
	}
	return NextMsgParams{Init: init}, nil

}

type extV5BetaSignedMessage struct {
	WalletId   WalletV5ID
	ValidUntil uint32
	Seqno      uint32
	Op         bool
	Actions    W5Actions `tlb:"^"`
}

func (w *walletV5Beta) CreateMsgBodyWithoutSignature(internalMessages []RawMessage, msgConfig MessageConfig) (*boc.Cell, error) {
	actions := make([]W5SendMessageAction, 0, len(internalMessages))
	for _, msg := range internalMessages {
		actions = append(actions, W5SendMessageAction{
			Msg:  msg.Message,
			Mode: msg.Mode,
		})
	}
	msg := extV5BetaSignedMessage{
		WalletId: WalletV5ID{
			NetworkGlobalID: w.networkGlobalID,
			Workchain:       uint8(w.workchain),
			SubWalletID:     w.subWalletID,
		},
		ValidUntil: uint32(msgConfig.ValidUntil.Unix()),
		Seqno:      msgConfig.Seqno,
		Op:         false,
		Actions:    actions,
	}
	bodyCell := boc.NewCell()
	if err := bodyCell.WriteUint(uint64(msgConfig.V5MsgType), 32); err != nil {
		return nil, err
	}
	if err := tlb.Marshal(bodyCell, msg); err != nil {
		return nil, err
	}
	bytes := [64]byte{}
	if err := bodyCell.WriteBytes(bytes[:]); err != nil {
		return nil, err
	}
	return bodyCell, nil

}

func (w *walletV5Beta) createSignedMsgBodyCell(signer signer.Signer, internalMessages []RawMessage, msgConfig MessageConfig) (*boc.Cell, error) {
	actions := make([]W5SendMessageAction, 0, len(internalMessages))
	for _, msg := range internalMessages {
		actions = append(actions, W5SendMessageAction{
			Msg:  msg.Message,
			Mode: msg.Mode,
		})
	}
	msg := extV5BetaSignedMessage{
		WalletId: WalletV5ID{
			NetworkGlobalID: w.networkGlobalID,
			Workchain:       uint8(w.workchain),
			SubWalletID:     w.subWalletID,
		},
		ValidUntil: uint32(msgConfig.ValidUntil.Unix()),
		Seqno:      msgConfig.Seqno,
		Op:         false,
		Actions:    actions,
	}
	bodyCell := boc.NewCell()
	if err := bodyCell.WriteUint(uint64(msgConfig.V5MsgType), 32); err != nil {
		return nil, err
	}
	if err := tlb.Marshal(bodyCell, msg); err != nil {
		return nil, err
	}
	signature, err := bodyCell.Sign(signer)
	if err != nil {
		return nil, err
	}
	if err := bodyCell.WriteBytes(signature); err != nil {
		return nil, err
	}
	return bodyCell, nil
}

func unpackAddr(wc int8, addr [32]byte) ton.AccountID {
	addr[31] = addr[31] ^ uint8(wc+1)
	return ton.AccountID{
		Workchain: int32(wc),
		Address:   addr,
	}
}

// GetW5BetaExtensionsList returns a list of wallet v5 beta extensions added to a specific wallet.
func GetW5BetaExtensionsList(state tlb.ShardAccount) (map[ton.AccountID]struct{}, error) {
	if state.Account.Status() == tlb.AccountActive {
		var data DataV5Beta
		cell := boc.Cell(state.Account.Account.Storage.State.AccountActive.StateInit.Data.Value.Value)
		if err := tlb.Unmarshal(&cell, &data); err != nil {
			return nil, err
		}
		if len(data.Extensions.Keys()) == 0 {
			return nil, nil
		}
		extensions := make(map[ton.AccountID]struct{}, len(data.Extensions.Keys()))
		for _, item := range data.Extensions.Items() {
			extensions[unpackAddr(int8(item.Value), item.Key)] = struct{}{}
		}
		return extensions, nil
	}
	return nil, nil
}
