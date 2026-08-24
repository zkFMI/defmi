package execute_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ava-labs/avalanchego/database/memdb"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/stretchr/testify/require"
	"github.com/shukob/defmi/avalanche/defmivm/execute"
	"github.com/shukob/defmi/avalanche/defmivm/state"
	"github.com/shukob/defmi/avalanche/defmivm/tx"
)

func id(label string) ids.ID { return ids.ID(sha256.Sum256([]byte(label))) }

func expected(t *testing.T, value string) ids.ID {
	bytes, err := hex.DecodeString(value)
	require.NoError(t, err)
	var result ids.ID
	copy(result[:], bytes)
	return result
}

const testDomain = "chain-test"

func committee() (tx.Committee, map[string]ed25519.PrivateKey) {
	members := make([]tx.CommitteeMember, 7)
	keys := make(map[string]ed25519.PrivateKey, 7)
	for i := range members {
		nodeID := "node-" + string(rune('0'+i))
		seed := sha256.Sum256([]byte("key:" + string(rune('0'+i))))
		private := ed25519.NewKeyFromSeed(seed[:])
		keys[nodeID] = private
		members[i].NodeID = nodeID
		copy(members[i].PublicKey[:], private.Public().(ed25519.PublicKey))
	}
	return tx.Committee{Epoch: 1, Threshold: 3, Members: members}, keys
}

func approved(t *testing.T, db *memdb.Database, statement ids.ID, committee tx.Committee,
	keys map[string]ed25519.PrivateKey) tx.QuorumApproval {
	before, err := state.StateRoot(db)
	require.NoError(t, err)
	return tx.NewApproval(statement, before, testDomain, committee,
		map[string]ed25519.PrivateKey{
			"node-0": keys["node-0"], "node-1": keys["node-1"],
			"node-2": keys["node-2"],
		})
}

func run(t *testing.T, db *memdb.Database, committee tx.Committee,
	unsigned tx.Unsigned) ids.ID {
	transaction := &tx.Tx{Unsigned: unsigned}
	require.NoError(t, execute.Check(
		db, committee, testDomain, time.Unix(100, 0), transaction))
	id, err := transaction.ID()
	require.NoError(t, err)
	return id
}

func TestPythonStatementAndStateRootCompatibility(t *testing.T) {
	committee, keys := committee()
	db := memdb.New()
	initial, err := state.StateRoot(db)
	require.NoError(t, err)
	require.Equal(t, expected(t, "9aec52fd1daadc2090f8c5bb3b26234b9f50343c6caf1c3244d53e4592a43d14"), initial)

	asset := tx.AssetDefinition{AssetID: id("asset:JPY"), Code: "JPY", Kind: "cash",
		TermsDigest: id("terms:JPY")}
	assetStatement, err := asset.Statement()
	require.NoError(t, err)
	require.Equal(t, expected(t, "70346f4cbc65320a60a5d13178b825120a5663efbd61c055c137ab042d9d2603"), assetStatement)
	run(t, db, committee, &tx.RegisterAsset{Asset: asset,
		Approval: approved(t, db, assetStatement, committee, keys)})
	root, err := state.StateRoot(db)
	require.NoError(t, err)
	require.Equal(t, expected(t, "bd06bb2506036e948b762f8b93bad194b843dc6b552332ca9d9d783f17ffc891"), root)

	left := tx.AccountOpening{Handle: id("left"), AssetID: asset.AssetID,
		Commitment: id("l0"), IssuanceNonce: id("li")}
	leftStatement, err := left.Statement()
	require.NoError(t, err)
	require.Equal(t, expected(t, "b1c6f2797a504b0ea3440376422bf4dcc118bca657931f7bd2a2100e5e390650"), leftStatement)
	run(t, db, committee, &tx.OpenAccount{Opening: left,
		Approval: approved(t, db, leftStatement, committee, keys)})
	root, err = state.StateRoot(db)
	require.NoError(t, err)
	require.Equal(t, expected(t, "3453f6a247c2da6b50f6f1d275195a16c671fd8be1080553a0f42b3cf29d2570"), root)

	right := tx.AccountOpening{Handle: id("right"), AssetID: asset.AssetID,
		Commitment: id("r0"), IssuanceNonce: id("ri")}
	rightStatement, err := right.Statement()
	require.NoError(t, err)
	require.Equal(t, expected(t, "5befedca26c9adec8202f62afc66e138d77c1628a65bfcc95def5976c7c7d73c"), rightStatement)
	run(t, db, committee, &tx.OpenAccount{Opening: right,
		Approval: approved(t, db, rightStatement, committee, keys)})
	root, err = state.StateRoot(db)
	require.NoError(t, err)
	require.Equal(t, expected(t, "b9a4e33932ace2397149836d5337391cdf3a620a31ea0d72f695d84cd38e032b"), root)

	order := tx.SettlementOrder{OperationID: id("operation"), Nullifier: id("nullifier"),
		Deadline: 1000, PaymentInstructionDigest: id("zkpi"), ProofDigest: id("proof"),
		MarketStatementDigest: id("market"), Legs: []tx.StateLeg{
			{Handle: left.Handle, AssetID: asset.AssetID, BeforeCommitment: id("l0"),
				AfterCommitment: id("l1")},
			{Handle: right.Handle, AssetID: asset.AssetID, BeforeCommitment: id("r0"),
				AfterCommitment: id("r1")},
		}}
	settlementStatement, err := order.Statement()
	require.NoError(t, err)
	require.Equal(t, expected(t, "a96760a0f07ec6c10383ff33b8f82c3625018bee3b0287f14a267ec85620c5eb"), settlementStatement)
	settlementTxID := run(t, db, committee, &tx.Settle{Order: order,
		Approval: approved(t, db, settlementStatement, committee, keys)})
	root, err = state.StateRoot(db)
	require.NoError(t, err)
	require.Equal(t, expected(t, "f78468ea6fb38616d7075ae687fe151f01b3cec6b2c6871b830af0b1b6d079e6"), root)
	record, err := state.GetTransition(db, settlementTxID)
	require.NoError(t, err)
	require.Equal(t, expected(t, "b9a4e33932ace2397149836d5337391cdf3a620a31ea0d72f695d84cd38e032b"), record.BeforeRoot)
	require.Equal(t, root, record.AfterRoot)
}

func TestThresholdStaleStateExpiryAndReplayFailClosed(t *testing.T) {
	committee, keys := committee()
	db := memdb.New()
	asset := tx.AssetDefinition{AssetID: id("asset"), Code: "JPY", Kind: "cash",
		TermsDigest: id("terms")}
	statement, err := asset.Statement()
	require.NoError(t, err)
	root, err := state.StateRoot(db)
	require.NoError(t, err)
	weak := &tx.RegisterAsset{Asset: asset, Approval: tx.NewApproval(
		statement, root, testDomain, committee,
		map[string]ed25519.PrivateKey{"node-0": keys["node-0"], "node-1": keys["node-1"]})}
	require.ErrorContains(t, execute.Check(db, committee, testDomain, time.Unix(100, 0),
		&tx.Tx{Unsigned: weak}), "threshold")
	_, err = state.GetAsset(db, asset.AssetID)
	require.ErrorIs(t, err, state.ErrUnknownAsset)

	run(t, db, committee, &tx.RegisterAsset{Asset: asset,
		Approval: approved(t, db, statement, committee, keys)})
	account := tx.AccountOpening{Handle: id("account"), AssetID: asset.AssetID,
		Commitment: id("c0"), IssuanceNonce: id("nonce")}
	accountStatement, _ := account.Statement()
	run(t, db, committee, &tx.OpenAccount{Opening: account,
		Approval: approved(t, db, accountStatement, committee, keys)})
	order := tx.SettlementOrder{OperationID: id("op"), Nullifier: id("null"),
		Deadline: 99, PaymentInstructionDigest: id("zkpi"), ProofDigest: id("proof"),
		MarketStatementDigest: id("market"), Legs: []tx.StateLeg{{
			Handle: account.Handle, AssetID: asset.AssetID,
			BeforeCommitment: id("wrong"), AfterCommitment: id("c1"),
		}}}
	orderStatement, _ := order.Statement()
	transaction := &tx.Tx{Unsigned: &tx.Settle{Order: order,
		Approval: approved(t, db, orderStatement, committee, keys)}}
	require.ErrorIs(t, execute.Check(
		db, committee, testDomain, time.Unix(100, 0), transaction), execute.ErrExpired)
	order.Deadline = 1000
	orderStatement, _ = order.Statement()
	transaction = &tx.Tx{Unsigned: &tx.Settle{Order: order,
		Approval: approved(t, db, orderStatement, committee, keys)}}
	require.ErrorIs(t, execute.Check(
		db, committee, testDomain, time.Unix(100, 0), transaction), execute.ErrStaleState)
	current, err := state.GetAccount(db, account.Handle)
	require.NoError(t, err)
	require.Equal(t, id("c0"), current.Commitment)
}

func TestApprovalDomainRootAndCommitteeKeysFailClosed(t *testing.T) {
	committee, keys := committee()
	db := memdb.New()
	pending := tx.AssetDefinition{AssetID: id("pending"), Code: "PENDING",
		Kind: "other", TermsDigest: id("pending-terms")}
	pendingStatement, err := pending.Statement()
	require.NoError(t, err)
	staleApproval := approved(t, db, pendingStatement, committee, keys)

	other := tx.AssetDefinition{AssetID: id("other"), Code: "OTHER",
		Kind: "other", TermsDigest: id("other-terms")}
	otherStatement, err := other.Statement()
	require.NoError(t, err)
	run(t, db, committee, &tx.RegisterAsset{Asset: other,
		Approval: approved(t, db, otherStatement, committee, keys)})
	pendingTx := &tx.Tx{Unsigned: &tx.RegisterAsset{
		Asset: pending, Approval: staleApproval}}
	require.ErrorContains(t, execute.Check(
		db, committee, testDomain, time.Unix(100, 0), pendingTx), "context")

	currentApproval := approved(t, db, pendingStatement, committee, keys)
	pendingTx = &tx.Tx{Unsigned: &tx.RegisterAsset{
		Asset: pending, Approval: currentApproval}}
	require.ErrorContains(t, execute.Check(
		db, committee, "another-chain", time.Unix(100, 0), pendingTx), "context")

	duplicate := committee
	duplicate.Members[1].PublicKey = duplicate.Members[0].PublicKey
	require.ErrorContains(t, duplicate.Validate(), "duplicate committee public key")
}

func TestEmptyIdentifiersAreRejected(t *testing.T) {
	_, err := (tx.AssetDefinition{Code: "JPY", Kind: "cash",
		TermsDigest: id("terms")}).Statement()
	require.ErrorContains(t, err, "asset code or decimals")
	_, err = (tx.AccountOpening{Handle: id("handle"), AssetID: id("asset"),
		IssuanceNonce: id("nonce")}).Statement()
	require.ErrorContains(t, err, "empty account field")
	_, err = (tx.SettlementOrder{OperationID: id("operation"), Deadline: 1000,
		PaymentInstructionDigest: id("zkpi"), ProofDigest: id("proof"),
		MarketStatementDigest: id("market"), Legs: []tx.StateLeg{{
			Handle: id("handle"), AssetID: id("asset"),
			BeforeCommitment: id("before"), AfterCommitment: id("after"),
		}}}).Statement()
	require.ErrorContains(t, err, "settlement dimensions")
}
