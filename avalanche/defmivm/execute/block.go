// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See THIRD_PARTY_NOTICES.md for the adapted XSVM source and license.

package execute

import (
	"errors"

	"github.com/ava-labs/avalanchego/database"
	"github.com/shukob/defmi/avalanche/defmivm/block"
	"github.com/shukob/defmi/avalanche/defmivm/state"
	"github.com/shukob/defmi/avalanche/defmivm/tx"
)

var ErrNoTxs = errors.New("block contains no transactions")

func Block(db database.Database, committee tx.Committee, domain string,
	blk *block.Stateless) error {
	if len(blk.Txs) == 0 {
		return ErrNoTxs
	}
	for _, transaction := range blk.Txs {
		if err := Check(db, committee, domain, blk.Time(), transaction); err != nil {
			return err
		}
	}
	blkID, err := blk.ID()
	if err != nil {
		return err
	}
	for _, transaction := range blk.Txs {
		txID, err := transaction.ID()
		if err != nil {
			return err
		}
		if err := state.FinalizeTransition(db, txID, blkID, blk.Height); err != nil {
			return err
		}
	}
	if err := state.SetLastAccepted(db, blkID); err != nil {
		return err
	}
	bytes, err := block.Codec.Marshal(block.CodecVersion, blk)
	if err != nil {
		return err
	}
	return state.AddBlock(db, blk.Height, blkID, bytes)
}
