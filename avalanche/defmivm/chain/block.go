// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See THIRD_PARTY_NOTICES.md for the adapted XSVM source and license.

package chain

import (
	"context"
	"errors"
	"time"

	"github.com/ava-labs/avalanchego/database"
	"github.com/ava-labs/avalanchego/database/versiondb"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/consensus/snowman"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/shukob/defmi/avalanche/defmivm/block"
	"github.com/shukob/defmi/avalanche/defmivm/execute"

	smblock "github.com/ava-labs/avalanchego/snow/engine/snowman/block"
)

const maxClockSkew = 10 * time.Second

var (
	_ Block = (*statefulBlock)(nil)

	ErrMissingParent         = errors.New("missing parent block")
	ErrMissingChild          = errors.New("missing child block")
	ErrParentNotVerified     = errors.New("parent block has not been verified")
	ErrFutureTimestamp       = errors.New("future timestamp")
	ErrTimestampBeforeParent = errors.New("timestamp before parent")
	ErrWrongHeight           = errors.New("wrong height")
)

type Block interface {
	snowman.Block
	smblock.WithVerifyContext
	State() (database.Database, error)
}

type statefulBlock struct {
	*block.Stateless
	chain            *chain
	id               ids.ID
	bytes            []byte
	state            *versiondb.Database
	verifiedChildren set.Set[ids.ID]
}

func (b *statefulBlock) ID() ids.ID           { return b.id }
func (b *statefulBlock) Parent() ids.ID       { return b.ParentID }
func (b *statefulBlock) Bytes() []byte        { return b.bytes }
func (b *statefulBlock) Height() uint64       { return b.Stateless.Height }
func (b *statefulBlock) Timestamp() time.Time { return b.Time() }

func (b *statefulBlock) Verify(ctx context.Context) error {
	return b.VerifyWithContext(ctx, nil)
}

func (b *statefulBlock) Accept(context.Context) error {
	if err := b.state.Commit(); err != nil {
		return err
	}
	for childID := range b.verifiedChildren {
		child, exists := b.chain.verified[childID]
		if !exists {
			return ErrMissingChild
		}
		if err := child.state.SetDatabase(b.chain.acceptedState); err != nil {
			return err
		}
	}
	b.chain.lastAccepted = b.id
	delete(b.chain.verified, b.ParentID)
	if b.chain.lifecycle != nil {
		b.chain.lifecycle.Accepted(b.Stateless.Txs)
	}
	b.state = nil
	return nil
}

func (b *statefulBlock) Reject(context.Context) error {
	delete(b.chain.verified, b.id)
	if b.chain.lifecycle != nil {
		b.chain.lifecycle.Rejected(b.Stateless.Txs)
	}
	b.state = nil
	return nil
}

func (*statefulBlock) ShouldVerifyWithContext(context.Context) (bool, error) {
	return false, nil
}

func (b *statefulBlock) VerifyWithContext(_ context.Context,
	_ *smblock.Context) error {
	if time.Until(b.Time()) > maxClockSkew {
		return ErrFutureTimestamp
	}
	parent, exists := b.chain.verified[b.ParentID]
	if !exists {
		return ErrMissingParent
	}
	if b.Stateless.Height != parent.Stateless.Height+1 {
		return ErrWrongHeight
	}
	if b.Time().Before(parent.Time()) {
		return ErrTimestampBeforeParent
	}
	parentState, err := parent.State()
	if err != nil {
		return err
	}
	blkState := versiondb.New(parentState)
	if err := execute.Block(
		blkState, b.chain.committee, b.chain.domain, b.Stateless); err != nil {
		return err
	}
	if b.state == nil {
		b.state = blkState
		parent.verifiedChildren.Add(b.id)
		b.chain.verified[b.id] = b
	}
	return nil
}

func (b *statefulBlock) State() (database.Database, error) {
	if b.id == b.chain.lastAccepted {
		return b.chain.acceptedState, nil
	}
	if b.state == nil {
		return nil, ErrParentNotVerified
	}
	return b.state, nil
}
