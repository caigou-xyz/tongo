package code

import (
	"reflect"
	"testing"

	"github.com/caigou-xyz/tongo/boc"
	"github.com/caigou-xyz/tongo/ton"
)

func TestFindLibraries(t *testing.T) {
	tests := []struct {
		name string
		boc  string
		want []ton.Bits256
	}{
		{
			name: "with library",
			boc:  "te6ccgEBAQEAIwAIQgJYfMeJ7/HIT0bsN5fkX8gJoU/1riTx4MemqZzJ3JBh/w==",
			want: []ton.Bits256{
				ton.MustParseHash("587CC789EFF1C84F46EC3797E45FC809A14FF5AE24F1E0C7A6A99CC9DC9061FF"),
			},
		},
		{
			name: "all good - this test doesn't work without ResetCounters()",
			boc:  "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",
			want: []ton.Bits256{
				ton.MustParseHash("50409510650018b849eee2c1d6c1ec8643438cea1c5b1b7bddb50c1ed86f832a"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cell, err := boc.DeserializeSinglRootBase64(tt.boc)
			if err != nil {
				t.Fatalf("DeserializeSinglRootBase64() failed: %v", err)
			}
			got, err := FindLibraries(cell)
			if err != nil {
				t.Fatalf("FindLibraries() failed: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindLibraries() got = %v, want %v", got, tt.want)
			}
		})
	}
}
