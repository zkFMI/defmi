// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See THIRD_PARTY_NOTICES.md for the adapted XSVM source and license.

package execute

import (
	"github.com/ava-labs/avalanchego/database"
	"github.com/shukob/defmi/avalanche/defmivm/block"
	"github.com/shukob/defmi/avalanche/defmivm/genesis"
	"github.com/shukob/defmi/avalanche/defmivm/state"
)

func Genesis(db database.Database, g *genesis.Genesis) error {
	initialized, err := state.IsInitialized(db)
	if err != nil || initialized {
		return err
	}
	blk, err := genesis.Block(g)
	if err != nil {
		return err
	}
	blkID, err := blk.ID()
	if err != nil {
		return err
	}
	bytes, err := block.Codec.Marshal(block.CodecVersion, blk)
	if err != nil {
		return err
	}
	if err := state.PutGenesis(db, g); err != nil {
		return err
	}
	if err := state.AddBlock(db, blk.Height, blkID, bytes); err != nil {
		return err
	}
	if err := state.SetLastAccepted(db, blkID); err != nil {
		return err
	}
	return state.SetInitialized(db)
}
