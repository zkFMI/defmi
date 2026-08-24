// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See THIRD_PARTY_NOTICES.md for the adapted XSVM source and license.

package chain

import (
	"github.com/ava-labs/avalanchego/database"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow"
	"github.com/shukob/defmi/avalanche/defmivm/block"
	"github.com/shukob/defmi/avalanche/defmivm/state"
	"github.com/shukob/defmi/avalanche/defmivm/tx"
)

type Chain interface {
	LastAccepted() ids.ID
	SetChainState(snow.State)
	SetLifecycle(TxLifecycle)
	GetBlock(ids.ID) (Block, error)
	NewBlock(*block.Stateless) (Block, error)
}

type TxLifecycle interface {
	Accepted([]*tx.Tx)
	Rejected([]*tx.Tx)
}

type chain struct {
	acceptedState database.Database
	committee     tx.Committee
	domain        string
	chainState    snow.State
	lastAccepted  ids.ID
	verified      map[ids.ID]*statefulBlock
	lifecycle     TxLifecycle
}

func New(db database.Database, committee tx.Committee, domain string) (Chain, error) {
	lastAccepted, err := state.GetLastAccepted(db)
	if err != nil {
		return nil, err
	}
	c := &chain{acceptedState: db, committee: committee, domain: domain,
		lastAccepted: lastAccepted}
	blk, err := c.getBlock(lastAccepted)
	if err != nil {
		return nil, err
	}
	c.verified = map[ids.ID]*statefulBlock{lastAccepted: blk}
	return c, nil
}

func (c *chain) LastAccepted() ids.ID           { return c.lastAccepted }
func (c *chain) SetChainState(value snow.State) { c.chainState = value }
func (c *chain) SetLifecycle(value TxLifecycle) { c.lifecycle = value }

func (c *chain) GetBlock(id ids.ID) (Block, error) { return c.getBlock(id) }

func (c *chain) NewBlock(stateless *block.Stateless) (Block, error) {
	id, err := stateless.ID()
	if err != nil {
		return nil, err
	}
	if known, exists := c.verified[id]; exists {
		return known, nil
	}
	bytes, err := block.Codec.Marshal(block.CodecVersion, stateless)
	if err != nil {
		return nil, err
	}
	return &statefulBlock{Stateless: stateless, chain: c, id: id, bytes: bytes}, nil
}

func (c *chain) getBlock(id ids.ID) (*statefulBlock, error) {
	if known, exists := c.verified[id]; exists {
		return known, nil
	}
	bytes, err := state.GetBlock(c.acceptedState, id)
	if err != nil {
		return nil, err
	}
	stateless, err := block.Parse(bytes)
	if err != nil {
		return nil, err
	}
	return &statefulBlock{Stateless: stateless, chain: c, id: id, bytes: bytes}, nil
}
