// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See THIRD_PARTY_NOTICES.md for the adapted XSVM source and license.

package block

import (
	"time"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/hashing"
	"github.com/shukob/defmi/avalanche/defmivm/tx"
)

type Stateless struct {
	ParentID  ids.ID   `serialize:"true" json:"parentID"`
	Timestamp int64    `serialize:"true" json:"timestamp"`
	Height    uint64   `serialize:"true" json:"height"`
	Txs       []*tx.Tx `serialize:"true" json:"txs"`
}

func (b *Stateless) Time() time.Time { return time.Unix(b.Timestamp, 0) }

func (b *Stateless) ID() (ids.ID, error) {
	bytes, err := Codec.Marshal(CodecVersion, b)
	return hashing.ComputeHash256Array(bytes), err
}

func Parse(bytes []byte) (*Stateless, error) {
	blk := &Stateless{}
	_, err := Codec.Unmarshal(bytes, blk)
	return blk, err
}
