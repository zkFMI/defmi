// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See THIRD_PARTY_NOTICES.md for the adapted XSVM source and license.

package defmivm

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ava-labs/avalanchego/database"
	"github.com/ava-labs/avalanchego/database/versiondb"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow"
	"github.com/ava-labs/avalanchego/snow/consensus/snowman"
	"github.com/ava-labs/avalanchego/snow/engine/common"
	"github.com/ava-labs/avalanchego/utils/json"
	"github.com/ava-labs/avalanchego/version"
	"github.com/gorilla/rpc/v2"
	"github.com/shukob/defmi/avalanche/defmivm/api"
	"github.com/shukob/defmi/avalanche/defmivm/block"
	"github.com/shukob/defmi/avalanche/defmivm/builder"
	"github.com/shukob/defmi/avalanche/defmivm/chain"
	"github.com/shukob/defmi/avalanche/defmivm/execute"
	"github.com/shukob/defmi/avalanche/defmivm/genesis"
	"github.com/shukob/defmi/avalanche/defmivm/state"
	"github.com/shukob/defmi/avalanche/defmivm/tx"

	smblock "github.com/ava-labs/avalanchego/snow/engine/snowman/block"
)

const Version = "v0.1.0"

const maxGossipTxBytes = 1 << 20

var (
	_ smblock.ChainVM                      = (*VM)(nil)
	_ smblock.BuildBlockWithContextChainVM = (*VM)(nil)
)

type VM struct {
	common.AppHandler
	ctx       *snow.Context
	db        database.Database
	appSender common.AppSender
	genesis   *genesis.Genesis
	chain     chain.Chain
	builder   builder.Builder
}

func (vm *VM) Initialize(_ context.Context, ctx *snow.Context,
	db database.Database, genesisBytes, _, _ []byte, _ []*common.Fx,
	appSender common.AppSender) error {
	g, err := genesis.Parse(genesisBytes)
	if err != nil {
		return fmt.Errorf("parse genesis: %w", err)
	}
	vdb := versiondb.New(db)
	if err := execute.Genesis(vdb, g); err != nil {
		return fmt.Errorf("initialize genesis: %w", err)
	}
	if err := vdb.Commit(); err != nil {
		return err
	}
	vm.ctx, vm.db, vm.genesis = ctx, db, g
	vm.appSender = appSender
	vm.AppHandler = common.NewNoOpAppHandler(ctx.Log)
	domain := ctx.ChainID.String()
	vm.chain, err = chain.New(db, g.Committee, domain)
	if err != nil {
		return fmt.Errorf("initialize chain: %w", err)
	}
	vm.builder = builder.New(vm.chain, g.Committee, domain)
	vm.chain.SetLifecycle(vm.builder)
	return nil
}

func (vm *VM) SetState(_ context.Context, value snow.State) error {
	vm.chain.SetChainState(value)
	return nil
}

func (vm *VM) Shutdown(context.Context) error {
	if vm.db == nil {
		return nil
	}
	return vm.db.Close()
}

func (*VM) Version(context.Context) (string, error) { return Version, nil }

func (vm *VM) CreateHandlers(context.Context) (map[string]http.Handler, error) {
	server := rpc.NewServer()
	server.RegisterCodec(json.NewCodec(), "application/json")
	server.RegisterCodec(json.NewCodec(), "application/json;charset=UTF-8")
	service := api.NewServer(vm.ctx, vm.genesis, vm.db, vm.chain, vm.builder,
		vm.gossip)
	return map[string]http.Handler{"": server}, server.RegisterService(service, "defmivm")
}

func (*VM) NewHTTPHandler(context.Context) (http.Handler, error) {
	return http.NotFoundHandler(), nil
}

func (*VM) Connected(context.Context, ids.NodeID, *version.Application) error {
	return nil
}

func (*VM) Disconnected(context.Context, ids.NodeID) error { return nil }

func (vm *VM) gossip(ctx context.Context, transaction *tx.Tx) error {
	if vm.appSender == nil {
		return fmt.Errorf("Avalanche app sender is unavailable")
	}
	bytes, err := transaction.Bytes()
	if err != nil {
		return err
	}
	if len(bytes) > maxGossipTxBytes {
		return fmt.Errorf("transaction exceeds gossip limit")
	}
	return vm.appSender.SendAppGossip(ctx, common.SendConfig{
		Validators: tx.MaxCommittee,
	}, bytes)
}

func (vm *VM) AppGossip(ctx context.Context, _ ids.NodeID, message []byte) error {
	if len(message) == 0 || len(message) > maxGossipTxBytes {
		return fmt.Errorf("invalid gossiped transaction size")
	}
	transaction, err := tx.Parse(message)
	if err != nil {
		return err
	}
	return vm.builder.AddTx(ctx, transaction)
}

func (*VM) HealthCheck(context.Context) (interface{}, error) {
	return http.StatusOK, nil
}

func (vm *VM) GetBlock(_ context.Context, id ids.ID) (snowman.Block, error) {
	return vm.chain.GetBlock(id)
}

func (vm *VM) ParseBlock(_ context.Context, bytes []byte) (snowman.Block, error) {
	parsed, err := block.Parse(bytes)
	if err != nil {
		return nil, err
	}
	return vm.chain.NewBlock(parsed)
}

func (vm *VM) WaitForEvent(ctx context.Context) (common.Message, error) {
	return vm.builder.WaitForEvent(ctx)
}

func (vm *VM) BuildBlock(ctx context.Context) (snowman.Block, error) {
	return vm.builder.BuildBlock(ctx)
}

func (vm *VM) SetPreference(_ context.Context, preferred ids.ID) error {
	vm.builder.SetPreference(preferred)
	return nil
}

func (vm *VM) LastAccepted(context.Context) (ids.ID, error) {
	return vm.chain.LastAccepted(), nil
}

func (vm *VM) BuildBlockWithContext(ctx context.Context,
	_ *smblock.Context) (snowman.Block, error) {
	return vm.builder.BuildBlock(ctx)
}

func (vm *VM) GetBlockIDAtHeight(_ context.Context, height uint64) (ids.ID, error) {
	return state.GetBlockIDByHeight(vm.db, height)
}
