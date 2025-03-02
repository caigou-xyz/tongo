package tlb

import (
	"fmt"
	"sort"

	"github.com/caigou-xyz/tongo/boc"
)

// BlockInfo
// block_info#9bc7a987 version:uint32
// not_master:(## 1)
// after_merge:(## 1) before_split:(## 1)
// after_split:(## 1)
// want_split:Bool want_merge:Bool
// key_block:Bool vert_seqno_incr:(## 1)
// flags:(## 8) { flags <= 1 }
// seq_no:# vert_seq_no:# { vert_seq_no >= vert_seqno_incr }
// { prev_seq_no:# } { ~prev_seq_no + 1 = seq_no }
// shard:ShardIdent gen_utime:uint32
// start_lt:uint64 end_lt:uint64
// gen_validator_list_hash_short:uint32
// gen_catchain_seqno:uint32
// min_ref_mc_seqno:uint32
// prev_key_block_seqno:uint32
// gen_software:flags . 0?GlobalVersion
// master_ref:not_master?^BlkMasterInfo
// prev_ref:^(BlkPrevInfo after_merge)
// prev_vert_ref:vert_seqno_incr?^(BlkPrevInfo 0)
// = BlockInfo;
type BlockInfo struct {
	BlockInfoPart
	GenSoftware *GlobalVersion
	MasterRef   *BlkMasterInfo
	PrevRef     BlkPrevInfo
	PrevVertRef *BlkPrevInfo
}

type BlockInfoPart struct {
	Version                   uint32
	NotMaster                 bool
	AfterMerge                bool
	BeforeSplit               bool
	AfterSplit                bool
	WantSplit                 bool
	WantMerge                 bool
	KeyBlock                  bool
	VertSeqnoIncr             bool
	Flags                     uint8
	SeqNo                     uint32
	VertSeqNo                 uint32
	Shard                     ShardIdent
	GenUtime                  uint32
	StartLt                   uint64
	EndLt                     uint64
	GenValidatorListHashShort uint32
	GenCatchainSeqno          uint32
	MinRefMcSeqno             uint32
	PrevKeyBlockSeqno         uint32
}

func (i *BlockInfo) UnmarshalTLB(c *boc.Cell, decoder *Decoder) error {
	var data struct {
		Magic     Magic `tlb:"block_info#9bc7a987"`
		BlockInfo BlockInfoPart
	} // for partial decoding
	err := decoder.Unmarshal(c, &data)
	if err != nil {
		return err
	}
	var res BlockInfo
	res.BlockInfoPart = data.BlockInfo

	if res.Flags&1 == 1 {
		var gs GlobalVersion
		err = decoder.Unmarshal(c, &gs)
		if err != nil {
			return err
		}
		res.GenSoftware = &gs
	}

	if data.BlockInfo.NotMaster {
		c1, err := c.NextRef()
		if err != nil {
			return err
		}
		res.MasterRef = &BlkMasterInfo{}
		err = decoder.Unmarshal(c1, res.MasterRef)
		if err != nil {
			return err
		}
	}

	c1, err := c.NextRef()
	if err != nil {
		return err
	}
	err = res.PrevRef.UnmarshalTLB(c1, data.BlockInfo.AfterMerge, decoder)
	if err != nil {
		return err
	}

	if data.BlockInfo.VertSeqnoIncr {
		c1, err = c.NextRef()
		if err != nil {
			return err
		}
		res.PrevVertRef = &BlkPrevInfo{}
		err = res.PrevVertRef.UnmarshalTLB(c1, false, decoder)
		if err != nil {
			return err
		}
	}
	*i = res
	return nil
}

// GlobalVersion
// capabilities#c4 version:uint32 capabilities:uint64 = GlobalVersion;
type GlobalVersion struct {
	Magic        Magic `tlb:"capabilities#c4"`
	Version      uint32
	Capabilities uint64
}

// ExtBlkRef
// ext_blk_ref$_ end_lt:uint64 seq_no:uint32 root_hash:bits256 file_hash:bits256 = ExtBlkRef;
type ExtBlkRef struct {
	EndLt    uint64
	SeqNo    uint32
	RootHash Bits256
	FileHash Bits256
}

// BlkMasterInfo
// master_info$_ master:ExtBlkRef = BlkMasterInfo;
// ext_blk_ref$_ end_lt:uint64 seq_no:uint32 root_hash:bits256 file_hash:bits256 = ExtBlkRef;
type BlkMasterInfo struct {
	Master ExtBlkRef
}

// BlkPrevInfo
// prev_blk_info$_ prev:ExtBlkRef = BlkPrevInfo 0;
// prev_blks_info$_ prev1:^ExtBlkRef prev2:^ExtBlkRef = BlkPrevInfo 1;
type BlkPrevInfo struct { // only manual decoding
	SumType
	PrevBlkInfo *struct {
		Prev ExtBlkRef
	} `tlbSumType:"prev_blk_info$_"`
	PrevBlksInfo *struct {
		Prev1 ExtBlkRef // ^ but decodes manually
		Prev2 ExtBlkRef // ^ but decodes manually
	} `tlbSumType:"prev_blks_info$_"`
}

func (i *BlkPrevInfo) UnmarshalTLB(c *boc.Cell, isBlks bool, decoder *Decoder) error { // custom unmarshaler. Not for automatic decoder.
	var res BlkPrevInfo
	if isBlks {
		var prev1, prev2 ExtBlkRef
		c1, err := c.NextRef()
		if err != nil {
			return err
		}
		err = decoder.Unmarshal(c1, &prev1)
		if err != nil {
			return err
		}
		c2, err := c.NextRef()
		if err != nil {
			return err
		}
		err = decoder.Unmarshal(c2, &prev2)
		if err != nil {
			return err
		}
		res.SumType = "PrevBlksInfo"
		res.PrevBlksInfo = &struct {
			Prev1 ExtBlkRef
			Prev2 ExtBlkRef
		}{Prev1: prev1, Prev2: prev2}
		*i = res
		return nil
	}
	var prev ExtBlkRef
	err := decoder.Unmarshal(c, &prev)
	if err != nil {
		return err
	}
	res.SumType = "PrevBlkInfo"
	res.PrevBlkInfo = &struct{ Prev ExtBlkRef }{Prev: prev}
	*i = res
	return nil
}

// Block
// block#11ef55aa global_id:int32
// info:^BlockInfo value_flow:^ValueFlow
// state_update:^(MERKLE_UPDATE ShardState)
// extra:^BlockExtra = Block;
type Block struct {
	Magic       Magic `tlb:"block#11ef55aa"`
	GlobalId    int32
	Info        BlockInfo                `tlb:"^"`
	ValueFlow   ValueFlow                `tlb:"^"`
	StateUpdate MerkleUpdate[ShardState] `tlb:"^"`
	Extra       BlockExtra               `tlb:"^"`
}

// TODO: clarify the description of the structure
type BlockHeader struct {
	Magic    Magic `tlb:"block#11ef55aa"`
	GlobalId int32
	Info     BlockInfo `tlb:"^"`
}

// block_proof#c3 proof_for:BlockIdExt root:^Cell signatures:(Maybe ^BlockSignatures) = BlockProof;
type BlockProof struct {
	Magic      Magic `tlb:"block_proof#c3"`
	ProofFor   BlockIdExt
	Root       boc.Cell `tlb:"^"`
	Signatures Maybe[Ref[BlockSignatures]]
}

// block_signatures#11 validator_info:ValidatorBaseInfo pure_signatures:BlockSignaturesPure = BlockSignatures;
type BlockSignatures struct {
	Magic          Magic `tlb:"block_signatures#11"`
	ValidatorInfo  ValidatorBaseInfo
	PureSignatures BlockSignaturesPure
}

// block_signatures_pure#_ sig_count:uint32 sig_weight:uint64
//   signatures:(HashmapE 16 CryptoSignaturePair) = BlockSignaturesPure;

type BlockSignaturesPure struct {
	SigCount   uint32
	SigWeight  uint64
	Signatures HashmapE[Uint16, CryptoSignaturePair]
}

// block_id_ext$_ shard_id:ShardIdent seq_no:uint32
// root_hash:bits256 file_hash:bits256 = BlockIdExt;
type BlockIdExt struct {
	ShardId  ShardIdent
	SeqNo    uint32
	RootHash Bits256
	FileHash Bits256
}

// ValueFlow
//
// v1:
// ^[ from_prev_blk:CurrencyCollection to_next_blk:CurrencyCollection imported:CurrencyCollection exported:CurrencyCollection ]
// fees_collected:CurrencyCollection
// ^[  fees_imported:CurrencyCollection recovered:CurrencyCollection  created:CurrencyCollection minted:CurrencyCollection
// ];
//
// v2:
//
//	^[ from_prev_blk:CurrencyCollection to_next_blk:CurrencyCollection imported:CurrencyCollection exported:CurrencyCollection ]
//	fees_collected: CurrencyCollection
//	burned: CurrencyCollection
//	^[ fees_imported:CurrencyCollection recovered:CurrencyCollection created:CurrencyCollection minted:CurrencyCollection ]
type ValueFlow struct {
	Magic         Magic `json:"-"`
	FromPrevBlk   CurrencyCollection
	ToNextBlk     CurrencyCollection
	Imported      CurrencyCollection
	Exported      CurrencyCollection
	FeesCollected CurrencyCollection
	Burned        *CurrencyCollection
	FeesImported  CurrencyCollection
	Recovered     CurrencyCollection
	Created       CurrencyCollection
	Minted        CurrencyCollection
}

const valueFlowV1 = 0xb8e48dfb
const valueFlowV2 = 0x3ebf98b7

func (m *ValueFlow) UnmarshalTLB(c *boc.Cell, decoder *Decoder) error {
	sumType, err := c.ReadUint(32)
	if err != nil {
		return err
	}
	if sumType != valueFlowV1 && sumType != valueFlowV2 {
		return fmt.Errorf("value flow invalid tag: %v", sumType)
	}
	m.Magic = Magic(sumType)
	firstGroup, err := c.NextRef()
	if err != nil {
		return err
	}
	err = decoder.Unmarshal(c, &m.FeesCollected)
	if err != nil {
		return err
	}
	err = decoder.Unmarshal(firstGroup, &m.FromPrevBlk)
	if err != nil {
		return err
	}
	err = decoder.Unmarshal(firstGroup, &m.ToNextBlk)
	if err != nil {
		return err
	}
	err = decoder.Unmarshal(firstGroup, &m.Imported)
	if err != nil {
		return err
	}
	err = decoder.Unmarshal(firstGroup, &m.Exported)
	if err != nil {
		return err
	}
	if sumType == valueFlowV2 {
		m.Burned = &CurrencyCollection{}
		err = decoder.Unmarshal(c, &m.Burned)
		if err != nil {
			return err
		}
	}
	secondGroup, err := c.NextRef()
	if err != nil {
		return err
	}
	err = decoder.Unmarshal(secondGroup, &m.FeesImported)
	if err != nil {
		return err
	}
	err = decoder.Unmarshal(secondGroup, &m.Recovered)
	if err != nil {
		return err
	}
	err = decoder.Unmarshal(secondGroup, &m.Created)
	if err != nil {
		return err
	}
	err = decoder.Unmarshal(secondGroup, &m.Minted)
	if err != nil {
		return err
	}
	return nil
}

// BlockExtra
// block_extra in_msg_descr:^InMsgDescr
// out_msg_descr:^OutMsgDescr
// account_blocks:^ShardAccountBlocks
// rand_seed:bits256
// created_by:bits256
// custom:(Maybe ^McBlockExtra) = BlockExtra;
type BlockExtra struct {
	Magic           Magic                                                  `tlb:"block_extra#4a33f6fd"`
	InMsgDescrCell  boc.Cell                                               `tlb:"^"`
	OutMsgDescrCell boc.Cell                                               `tlb:"^"`
	AccountBlocks   HashmapAugE[Bits256, AccountBlock, CurrencyCollection] `tlb:"^"`
	RandSeed        Bits256
	CreatedBy       Bits256
	Custom          Maybe[Ref[McBlockExtra]]
}

func (extra *BlockExtra) InMsgDescrLength() (int, error) {
	cell := boc.Cell(extra.InMsgDescrCell)
	cell.ResetCounters()
	return hashmapAugExtraCountLeafs[Bits256](&cell)
}

func (extra *BlockExtra) InMsgDescr() (HashmapAugE[Bits256, InMsg, ImportFees], error) {
	var hashmap HashmapAugE[Bits256, InMsg, ImportFees]
	if err := Unmarshal(&extra.InMsgDescrCell, &hashmap); err != nil {
		return HashmapAugE[Bits256, InMsg, ImportFees]{}, err
	}
	return hashmap, nil
}

func (extra *BlockExtra) OutMsgDescrLength() (int, error) {
	cell := boc.Cell(extra.OutMsgDescrCell)
	cell.ResetCounters()
	return hashmapAugExtraCountLeafs[Bits256](&cell)
}

func (extra *BlockExtra) OutMsgDescr() (HashmapAugE[Bits256, OutMsg, CurrencyCollection], error) {
	var hashmap HashmapAugE[Bits256, OutMsg, CurrencyCollection]
	if err := Unmarshal(&extra.OutMsgDescrCell, &hashmap); err != nil {
		return HashmapAugE[Bits256, OutMsg, CurrencyCollection]{}, err
	}
	return hashmap, nil
}

// masterchain_block_extra#cca5
//
//	key_block:(## 1)
//	shard_hashes:ShardHashes
//	shard_fees:ShardFees
//	^[ prev_blk_signatures:(HashmapE 16 CryptoSignaturePair)
//	   recover_create_msg:(Maybe ^InMsg)
//	   mint_msg:(Maybe ^InMsg) ]
//	config:key_block?ConfigParams
//
// = McBlockExtra;
type McBlockExtra struct {
	Magic        Magic `tlb:"masterchain_block_extra#cca5"`
	KeyBlock     bool
	ShardHashes  HashmapE[Uint32, Ref[ShardInfoBinTree]]
	ShardFees    ShardFees
	McExtraOther struct {
		PrevBlkSignatures HashmapE[Uint16, CryptoSignaturePair]
		RecoverCreate     Maybe[Ref[InMsg]]
		MintMsg           Maybe[Ref[InMsg]]
	} `tlb:"^"`
	Config ConfigParams
}

func (m *McBlockExtra) UnmarshalTLB(c *boc.Cell, decoder *Decoder) error {
	sumType, err := c.ReadUint(16)
	if err != nil {
		return err
	}
	if sumType != 0xcca5 {
		return fmt.Errorf("invalid tag")
	}

	err = decoder.Unmarshal(c, &m.KeyBlock)
	if err != nil {
		return err
	}
	err = decoder.Unmarshal(c, &m.ShardHashes)
	if err != nil {
		return err
	}
	err = decoder.Unmarshal(c, &m.ShardFees)
	if err != nil {
		return err
	}
	c1, err := c.NextRef()
	if err != nil && err != boc.ErrNotEnoughRefs {
		return err
	}

	if c1 != nil {
		err = decoder.Unmarshal(c1, &m.McExtraOther)
		if err != nil {
			return err
		}
	}
	if m.KeyBlock {
		err = decoder.Unmarshal(c, &m.Config)
		if err != nil {
			return err
		}
	}
	return nil
}

// TransactionsQuantity returns the number of transactions in this block.
func (b *Block) TransactionsQuantity() int {
	quantity := 0
	for _, accountBlock := range b.Extra.AccountBlocks.Values() {
		quantity += len(accountBlock.Transactions.keys)
	}
	return quantity
}

// AllTransactions returns all transactions in this block ordered by Lt.
func (b *Block) AllTransactions() []*Transaction {
	transactions := make([]*Transaction, 0, b.TransactionsQuantity())
	for _, accountBlock := range b.Extra.AccountBlocks.Values() {
		for i := range accountBlock.Transactions.values {
			transactions = append(transactions, &accountBlock.Transactions.values[i].Value)
		}
	}
	sort.Slice(transactions, func(i, j int) bool {
		return transactions[i].Lt < transactions[j].Lt
	})
	return transactions
}
