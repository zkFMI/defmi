package execute

import (
	"errors"
	"fmt"
	"time"

	"github.com/ava-labs/avalanchego/database"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/shukob/defmi/avalanche/defmivm/state"
	"github.com/shukob/defmi/avalanche/defmivm/tx"
)

var (
	_ tx.Visitor = (*Tx)(nil)

	ErrExpired        = errors.New("payment instruction expired")
	ErrStaleState     = errors.New("settlement references stale state")
	ErrWrongAssetRail = errors.New("settlement uses the wrong asset rail")
	ErrDuplicate      = errors.New("transition is already present")
)

type Tx struct {
	Database  database.Database
	Committee tx.Committee
	Domain    string
	Timestamp time.Time
	TxID      ids.ID
}

func (t *Tx) record(statement, before, after ids.ID) error {
	return state.SetTransition(t.Database, t.TxID, state.TransitionRecord{
		Statement: statement, BeforeRoot: before, AfterRoot: after,
	})
}

func (t *Tx) authorize(statement ids.ID, approval tx.QuorumApproval) (ids.ID, error) {
	before, err := state.StateRoot(t.Database)
	if err != nil {
		return ids.Empty, err
	}
	if err := approval.Verify(t.Committee, t.Domain, before, statement); err != nil {
		return ids.Empty, err
	}
	return before, nil
}

func (t *Tx) RegisterAsset(action *tx.RegisterAsset) error {
	statement, err := action.Asset.Statement()
	if err != nil {
		return err
	}
	before, err := t.authorize(statement, action.Approval)
	if err != nil {
		return err
	}
	if err := state.AddAsset(t.Database, action.Asset); err != nil {
		if errors.Is(err, state.ErrAlreadyExists) {
			return ErrDuplicate
		}
		return err
	}
	after, err := state.StateRoot(t.Database)
	if err != nil {
		return err
	}
	return t.record(statement, before, after)
}

func (t *Tx) OpenAccount(action *tx.OpenAccount) error {
	statement, err := action.Opening.Statement()
	if err != nil {
		return err
	}
	before, err := t.authorize(statement, action.Approval)
	if err != nil {
		return err
	}
	if err := state.AddAccount(t.Database, action.Opening); err != nil {
		if errors.Is(err, state.ErrAlreadyExists) {
			return ErrDuplicate
		}
		return err
	}
	after, err := state.StateRoot(t.Database)
	if err != nil {
		return err
	}
	return t.record(statement, before, after)
}

func (t *Tx) Settle(action *tx.Settle) error {
	statement, err := action.Order.Statement()
	if err != nil {
		return err
	}
	before, err := t.authorize(statement, action.Approval)
	if err != nil {
		return err
	}
	if t.Timestamp.Unix() > int64(action.Order.Deadline) {
		return ErrExpired
	}
	if exists, err := state.HasOperation(t.Database, action.Order.OperationID); err != nil {
		return err
	} else if exists {
		return ErrDuplicate
	}
	if exists, err := state.HasNullifier(t.Database, action.Order.Nullifier); err != nil {
		return err
	} else if exists {
		return state.ErrAlreadySettled
	}
	for _, leg := range action.Order.Legs {
		if leg.BeforeSequence == ^uint64(0) {
			return fmt.Errorf("%w: account sequence overflow", tx.ErrInvalidTransition)
		}
		account, err := state.GetAccount(t.Database, leg.Handle)
		if err != nil {
			return err
		}
		if account.AssetID != leg.AssetID {
			return ErrWrongAssetRail
		}
		if account.Commitment != leg.BeforeCommitment ||
			account.Sequence != leg.BeforeSequence {
			return ErrStaleState
		}
		asset, err := state.GetAsset(t.Database, leg.AssetID)
		if err != nil || !asset.Active {
			return state.ErrUnknownAsset
		}
	}
	if err := state.AddNullifier(t.Database, action.Order.Nullifier,
		action.Order.Deadline, statement); err != nil {
		return err
	}
	if err := state.AddOperation(t.Database, action.Order.OperationID, statement); err != nil {
		return err
	}
	for _, leg := range action.Order.Legs {
		if err := state.SetAccount(t.Database, leg.Handle, state.AccountRecord{
			AssetID: leg.AssetID, Commitment: leg.AfterCommitment,
			Sequence: leg.BeforeSequence + 1,
		}); err != nil {
			return err
		}
	}
	after, err := state.StateRoot(t.Database)
	if err != nil {
		return err
	}
	return t.record(statement, before, after)
}

func Check(db database.Database, committee tx.Committee, domain string,
	timestamp time.Time, transaction *tx.Tx) error {
	txID, err := transaction.ID()
	if err != nil {
		return err
	}
	executor := Tx{Database: db, Committee: committee, Domain: domain,
		Timestamp: timestamp, TxID: txID}
	return transaction.Unsigned.Visit(&executor)
}
