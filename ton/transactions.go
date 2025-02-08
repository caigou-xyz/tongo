package ton

import "github.com/caigou-xyz/tongo/tlb"

type Transaction struct {
	tlb.Transaction
	BlockID BlockIDExt
}
