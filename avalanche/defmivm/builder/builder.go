// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See THIRD_PARTY_NOTICES.md for the adapted XSVM source and license.

package builder

import (
	"context"
	"sync"
	"time"

	"github.com/ava-labs/avalanchego/database/versiondb"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/engine/common"
	"github.com/ava-labs/avalanchego/utils/linked"
	"github.com/ava-labs/avalanchego/utils/lock"
	"github.com/shukob/defmi/avalanche/defmivm/block"
	"github.com/shukob/defmi/avalanche/defmivm/chain"
	"github.com/shukob/defmi/avalanche/defmivm/execute"
	"github.com/shukob/defmi/avalanche/defmivm/tx"
)

const MaxTxsPerBlock = 32

type Builder interface {
	SetPreference(ids.ID)
	AddTx(context.Context, *tx.Tx) error
	LookupTx(ids.ID) (string, string)
	Accepted([]*tx.Tx)
	Rejected([]*tx.Tx)
	WaitForEvent(context.Context) (common.Message, error)
	BuildBlock(context.Context) (chain.Block, error)
}

type builder struct {
	chain       chain.Chain
	committee   tx.Committee
	domain      string
	preference  ids.ID
	pendingCond *lock.Cond
	pending     *linked.Hashmap[ids.ID, *tx.Tx]
	processing  map[ids.ID]*tx.Tx
	rejected    *linked.Hashmap[ids.ID, string]
}

const maxRememberedRejections = 4096

func New(chain chain.Chain, committee tx.Committee, domain string) Builder {
	return &builder{chain: chain, committee: committee, domain: domain,
		preference: chain.LastAccepted(), pendingCond: lock.NewCond(&sync.Mutex{}),
		pending:    linked.NewHashmap[ids.ID, *tx.Tx](),
		processing: make(map[ids.ID]*tx.Tx),
		rejected:   linked.NewHashmap[ids.ID, string]()}
}

func (b *builder) SetPreference(preferred ids.ID) { b.preference = preferred }

func (b *builder) AddTx(_ context.Context, transaction *tx.Tx) error {
	txID, err := transaction.ID()
	if err != nil {
		return err
	}
	preferred, err := b.chain.GetBlock(b.preference)
	if err != nil {
		return err
	}
	preferredState, err := preferred.State()
	if err != nil {
		return err
	}
	probe := versiondb.New(preferredState)
	if err := execute.Check(probe, b.committee, b.domain, time.Now().Truncate(time.Second),
		transaction); err != nil {
		return err
	}
	b.pendingCond.L.Lock()
	defer b.pendingCond.L.Unlock()
	if _, exists := b.processing[txID]; exists {
		return nil
	}
	b.rejected.Delete(txID)
	b.pending.Put(txID, transaction)
	b.pendingCond.Broadcast()
	return nil
}

func (b *builder) LookupTx(txID ids.ID) (string, string) {
	b.pendingCond.L.Lock()
	defer b.pendingCond.L.Unlock()
	if _, exists := b.pending.Get(txID); exists {
		return "pending", ""
	}
	if _, exists := b.processing[txID]; exists {
		return "processing", ""
	}
	if reason, exists := b.rejected.Get(txID); exists {
		return "rejected", reason
	}
	return "unknown", ""
}

func (b *builder) Accepted(transactions []*tx.Tx) {
	b.pendingCond.L.Lock()
	defer b.pendingCond.L.Unlock()
	for _, transaction := range transactions {
		txID, err := transaction.ID()
		if err != nil {
			continue
		}
		b.pending.Delete(txID)
		delete(b.processing, txID)
		b.rejected.Delete(txID)
	}
}

func (b *builder) Rejected(transactions []*tx.Tx) {
	b.pendingCond.L.Lock()
	defer b.pendingCond.L.Unlock()
	for _, transaction := range transactions {
		txID, err := transaction.ID()
		if err != nil {
			continue
		}
		delete(b.processing, txID)
		b.pending.Put(txID, transaction)
	}
	b.pendingCond.Broadcast()
}

func (b *builder) rememberRejected(txID ids.ID, reason string) {
	b.rejected.Put(txID, reason)
	for b.rejected.Len() > maxRememberedRejections {
		oldest, _, exists := b.rejected.Oldest()
		if !exists {
			break
		}
		b.rejected.Delete(oldest)
	}
}

func (b *builder) WaitForEvent(ctx context.Context) (common.Message, error) {
	b.pendingCond.L.Lock()
	defer b.pendingCond.L.Unlock()
	for b.pending.Len() == 0 {
		if err := b.pendingCond.Wait(ctx); err != nil {
			return 0, err
		}
	}
	return common.PendingTxs, nil
}

func (b *builder) BuildBlock(_ context.Context) (chain.Block, error) {
	preferred, err := b.chain.GetBlock(b.preference)
	if err != nil {
		return nil, err
	}
	preferredState, err := preferred.State()
	if err != nil {
		return nil, err
	}
	timestamp := time.Now().Truncate(time.Second)
	if timestamp.Before(preferred.Timestamp()) {
		timestamp = preferred.Timestamp()
	}
	wip := block.Stateless{ParentID: b.preference, Timestamp: timestamp.Unix(),
		Height: preferred.Height() + 1}
	b.pendingCond.L.Lock()
	defer b.pendingCond.L.Unlock()
	current := versiondb.New(preferredState)
	for len(wip.Txs) < MaxTxsPerBlock {
		txID, transaction, exists := b.pending.Oldest()
		if !exists {
			break
		}
		b.pending.Delete(txID)
		probe := versiondb.New(current)
		if err := execute.Check(
			probe, b.committee, b.domain, timestamp, transaction); err != nil {
			b.rememberRejected(txID, err.Error())
			continue
		}
		if err := probe.Commit(); err != nil {
			b.pending.Put(txID, transaction)
			return nil, err
		}
		b.processing[txID] = transaction
		wip.Txs = append(wip.Txs, transaction)
	}
	built, err := b.chain.NewBlock(&wip)
	if err != nil {
		for _, transaction := range wip.Txs {
			txID, idErr := transaction.ID()
			if idErr != nil {
				continue
			}
			delete(b.processing, txID)
			b.pending.Put(txID, transaction)
		}
		b.pendingCond.Broadcast()
		return nil, err
	}
	return built, nil
}
