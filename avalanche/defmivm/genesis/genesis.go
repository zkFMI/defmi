package genesis

import (
	"fmt"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/hashing"
	"github.com/shukob/defmi/avalanche/defmivm/block"
	"github.com/shukob/defmi/avalanche/defmivm/tx"
)

type Genesis struct {
	Timestamp int64        `serialize:"true" json:"timestamp"`
	Committee tx.Committee `serialize:"true" json:"committee"`
}

func (g *Genesis) Validate() error {
	if g.Timestamp < 0 {
		return fmt.Errorf("genesis timestamp cannot be negative")
	}
	return g.Committee.Validate()
}

func Parse(bytes []byte) (*Genesis, error) {
	genesis := &Genesis{}
	if _, err := Codec.Unmarshal(bytes, genesis); err != nil {
		return nil, err
	}
	return genesis, genesis.Validate()
}

func Marshal(genesis *Genesis) ([]byte, error) {
	if err := genesis.Validate(); err != nil {
		return nil, err
	}
	return Codec.Marshal(CodecVersion, genesis)
}

func Block(genesis *Genesis) (*block.Stateless, error) {
	bytes, err := Marshal(genesis)
	if err != nil {
		return nil, err
	}
	return &block.Stateless{
		ParentID:  ids.ID(hashing.ComputeHash256Array(bytes)),
		Timestamp: genesis.Timestamp,
	}, nil
}
