package chain_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/ava-labs/avalanchego/database/memdb"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/stretchr/testify/require"
	"github.com/shukob/defmi/avalanche/defmivm/builder"
	"github.com/shukob/defmi/avalanche/defmivm/chain"
	"github.com/shukob/defmi/avalanche/defmivm/execute"
	"github.com/shukob/defmi/avalanche/defmivm/genesis"
	"github.com/shukob/defmi/avalanche/defmivm/state"
	"github.com/shukob/defmi/avalanche/defmivm/tx"
)

func testID(label string) ids.ID { return ids.ID(sha256.Sum256([]byte(label))) }

const testDomain = "chain-test"

func testCommittee() (tx.Committee, map[string]ed25519.PrivateKey) {
	members := make([]tx.CommitteeMember, 7)
	keys := make(map[string]ed25519.PrivateKey, 7)
	for i := range members {
		node := fmt.Sprintf("node-%d", i)
		seed := sha256.Sum256([]byte("key:" + node))
		private := ed25519.NewKeyFromSeed(seed[:])
		keys[node] = private
		members[i].NodeID = node
		copy(members[i].PublicKey[:], private.Public().(ed25519.PublicKey))
	}
	return tx.Committee{Epoch: 1, Threshold: 3, Members: members}, keys
}

func approval(t *testing.T, db *memdb.Database, statement ids.ID, committee tx.Committee,
	keys map[string]ed25519.PrivateKey) tx.QuorumApproval {
	before, err := state.StateRoot(db)
	require.NoError(t, err)
	return tx.NewApproval(statement, before, testDomain, committee,
		map[string]ed25519.PrivateKey{
			"node-0": keys["node-0"], "node-1": keys["node-1"],
			"node-2": keys["node-2"],
		})
}

func TestNativeAvalancheBlockLifecycleAndRestart(t *testing.T) {
	committee, keys := testCommittee()
	db := memdb.New()
	require.NoError(t, execute.Genesis(db, &genesis.Genesis{
		Timestamp: 0, Committee: committee,
	}))
	c, err := chain.New(db, committee, testDomain)
	require.NoError(t, err)
	b := builder.New(c, committee, testDomain)
	c.SetLifecycle(b)

	acceptTx := func(transaction *tx.Tx) ids.ID {
		ctx := context.Background()
		require.NoError(t, b.AddTx(ctx, transaction))
		txID, err := transaction.ID()
		require.NoError(t, err)
		status, reason := b.LookupTx(txID)
		require.Equal(t, "pending", status)
		require.Empty(t, reason)
		blk, err := b.BuildBlock(ctx)
		require.NoError(t, err)
		status, reason = b.LookupTx(txID)
		require.Equal(t, "processing", status)
		require.Empty(t, reason)
		require.NoError(t, blk.Verify(ctx))
		require.NoError(t, blk.Accept(ctx))
		status, reason = b.LookupTx(txID)
		require.Equal(t, "unknown", status)
		require.Empty(t, reason)
		b.SetPreference(blk.ID())
		record, err := state.GetTransition(db, txID)
		require.NoError(t, err)
		require.Equal(t, blk.ID(), record.BlockID)
		require.Equal(t, blk.Height(), record.Height)
		return txID
	}

	asset := tx.AssetDefinition{AssetID: testID("asset"), Code: "JPY", Kind: "cash",
		TermsDigest: testID("terms")}
	assetStatement, _ := asset.Statement()
	acceptTx(&tx.Tx{Unsigned: &tx.RegisterAsset{Asset: asset,
		Approval: approval(t, db, assetStatement, committee, keys)}})

	left := tx.AccountOpening{Handle: testID("left"), AssetID: asset.AssetID,
		Commitment: testID("l0"), IssuanceNonce: testID("li")}
	leftStatement, _ := left.Statement()
	acceptTx(&tx.Tx{Unsigned: &tx.OpenAccount{Opening: left,
		Approval: approval(t, db, leftStatement, committee, keys)}})
	right := tx.AccountOpening{Handle: testID("right"), AssetID: asset.AssetID,
		Commitment: testID("r0"), IssuanceNonce: testID("ri")}
	rightStatement, _ := right.Statement()
	acceptTx(&tx.Tx{Unsigned: &tx.OpenAccount{Opening: right,
		Approval: approval(t, db, rightStatement, committee, keys)}})

	order := tx.SettlementOrder{OperationID: testID("operation"),
		Nullifier: testID("nullifier"), Deadline: uint64(time.Now().Unix() + 300),
		PaymentInstructionDigest: testID("zkpi"), ProofDigest: testID("proof"),
		MarketStatementDigest: testID("market"), Legs: []tx.StateLeg{
			{Handle: left.Handle, AssetID: asset.AssetID,
				BeforeCommitment: testID("l0"), AfterCommitment: testID("l1")},
			{Handle: right.Handle, AssetID: asset.AssetID,
				BeforeCommitment: testID("r0"), AfterCommitment: testID("r1")},
		}}
	orderStatement, _ := order.Statement()
	settlementID := acceptTx(&tx.Tx{Unsigned: &tx.Settle{Order: order,
		Approval: approval(t, db, orderStatement, committee, keys)}})

	leftState, err := state.GetAccount(db, left.Handle)
	require.NoError(t, err)
	require.Equal(t, testID("l1"), leftState.Commitment)
	require.Equal(t, uint64(1), leftState.Sequence)
	acceptedBeforeRestart, err := state.GetTransition(db, settlementID)
	require.NoError(t, err)

	restarted, err := chain.New(db, committee, testDomain)
	require.NoError(t, err)
	require.Equal(t, c.LastAccepted(), restarted.LastAccepted())
	acceptedAfterRestart, err := state.GetTransition(db, settlementID)
	require.NoError(t, err)
	require.Equal(t, acceptedBeforeRestart, acceptedAfterRestart)

	retryAsset := tx.AssetDefinition{AssetID: testID("retry-asset"), Code: "USD",
		Kind: "cash", TermsDigest: testID("retry-terms")}
	retryStatement, err := retryAsset.Statement()
	require.NoError(t, err)
	retryTx := &tx.Tx{Unsigned: &tx.RegisterAsset{Asset: retryAsset,
		Approval: approval(t, db, retryStatement, committee, keys)}}
	require.NoError(t, b.AddTx(context.Background(), retryTx))
	retryBlock, err := b.BuildBlock(context.Background())
	require.NoError(t, err)
	retryID, err := retryTx.ID()
	require.NoError(t, err)
	status, _ := b.LookupTx(retryID)
	require.Equal(t, "processing", status)
	require.NoError(t, retryBlock.Reject(context.Background()))
	status, _ = b.LookupTx(retryID)
	require.Equal(t, "pending", status)
}
