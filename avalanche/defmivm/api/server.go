package api

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/ava-labs/avalanchego/database"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow"
	"github.com/shukob/defmi/avalanche/defmivm/builder"
	"github.com/shukob/defmi/avalanche/defmivm/chain"
	"github.com/shukob/defmi/avalanche/defmivm/genesis"
	"github.com/shukob/defmi/avalanche/defmivm/state"
	"github.com/shukob/defmi/avalanche/defmivm/tx"
)

type Server struct {
	ctx     *snow.Context
	genesis *genesis.Genesis
	state   database.Database
	chain   chain.Chain
	builder builder.Builder
	gossip  func(context.Context, *tx.Tx) error
}

func NewServer(ctx *snow.Context, genesis *genesis.Genesis,
	state database.Database, chain chain.Chain, builder builder.Builder,
	gossip func(context.Context, *tx.Tx) error) *Server {
	return &Server{ctx: ctx, genesis: genesis, state: state, chain: chain,
		builder: builder, gossip: gossip}
}

type NetworkReply struct {
	NetworkID uint32 `json:"networkID"`
	SubnetID  ids.ID `json:"subnetID"`
	ChainID   ids.ID `json:"chainID"`
}

func (s *Server) Network(_ *http.Request, _ *struct{}, reply *NetworkReply) error {
	reply.NetworkID = s.ctx.NetworkID
	reply.SubnetID = s.ctx.SubnetID
	reply.ChainID = s.ctx.ChainID
	return nil
}

type GenesisReply struct {
	Genesis *genesis.Genesis `json:"genesis"`
}

func (s *Server) Genesis(_ *http.Request, _ *struct{}, reply *GenesisReply) error {
	reply.Genesis = s.genesis
	return nil
}

type StateRootReply struct {
	StateRoot string `json:"stateRoot"`
}

func (s *Server) StateRoot(_ *http.Request, _ *struct{}, reply *StateRootReply) error {
	s.ctx.Lock.RLock()
	defer s.ctx.Lock.RUnlock()
	root, err := state.StateRoot(s.state)
	reply.StateRoot = hex.EncodeToString(root[:])
	return err
}

type ApprovalArgs struct {
	Statement   string             `json:"statement"`
	SignerEpoch uint64             `json:"signerEpoch"`
	Domain      string             `json:"domain"`
	BeforeRoot  string             `json:"beforeRoot"`
	Approvals   []NodeApprovalArgs `json:"approvals"`
}

type NodeApprovalArgs struct {
	NodeID    string `json:"nodeID"`
	Signature string `json:"signature"`
}

func (a ApprovalArgs) parse() (tx.QuorumApproval, error) {
	statement, err := parseID(a.Statement, "statement")
	if err != nil {
		return tx.QuorumApproval{}, err
	}
	beforeRoot, err := parseID(a.BeforeRoot, "beforeRoot")
	if err != nil {
		return tx.QuorumApproval{}, err
	}
	if len(a.Domain) == 0 || len(a.Domain) > tx.MaxDomainLen {
		return tx.QuorumApproval{}, fmt.Errorf("approval domain has invalid length")
	}
	if len(a.Approvals) > tx.MaxApprovals {
		return tx.QuorumApproval{}, fmt.Errorf("too many approvals")
	}
	result := tx.QuorumApproval{Statement: statement, SignerEpoch: a.SignerEpoch,
		Domain: a.Domain, BeforeRoot: beforeRoot,
		Approvals: make([]tx.NodeApproval, len(a.Approvals))}
	for i, item := range a.Approvals {
		decoded, err := hex.DecodeString(item.Signature)
		if err != nil || len(decoded) != ed25519.SignatureSize {
			return tx.QuorumApproval{}, fmt.Errorf("approval %d has invalid signature", i)
		}
		result.Approvals[i].NodeID = item.NodeID
		copy(result.Approvals[i].Signature[:], decoded)
	}
	return result, nil
}

type AssetArgs struct {
	AssetID     string `json:"assetID"`
	Code        string `json:"code"`
	Kind        string `json:"kind"`
	Decimals    uint8  `json:"decimals"`
	TermsDigest string `json:"termsDigest"`
}

func (a AssetArgs) parse() (tx.AssetDefinition, error) {
	assetID, err := parseID(a.AssetID, "assetID")
	if err != nil {
		return tx.AssetDefinition{}, err
	}
	terms, err := parseID(a.TermsDigest, "termsDigest")
	if err != nil {
		return tx.AssetDefinition{}, err
	}
	result := tx.AssetDefinition{AssetID: assetID, Code: a.Code, Kind: a.Kind,
		Decimals: a.Decimals, TermsDigest: terms}
	return result, result.Validate()
}

type IssueAssetArgs struct {
	Asset              AssetArgs    `json:"asset"`
	Approval           ApprovalArgs `json:"approval"`
	ExpectedBeforeRoot string       `json:"expectedBeforeRoot"`
}

type IssueTxReply struct {
	TxID ids.ID `json:"txID"`
}

func (s *Server) IssueAsset(r *http.Request, args *IssueAssetArgs,
	reply *IssueTxReply) error {
	asset, err := args.Asset.parse()
	if err != nil {
		return err
	}
	approval, err := args.Approval.parse()
	if err != nil {
		return err
	}
	expectedBeforeRoot, err := parseID(args.ExpectedBeforeRoot, "expectedBeforeRoot")
	if err != nil {
		return err
	}
	if approval.BeforeRoot != expectedBeforeRoot {
		return fmt.Errorf("approval is bound to another state root")
	}
	return s.issue(r, &tx.Tx{Unsigned: &tx.RegisterAsset{
		Asset: asset, Approval: approval}}, expectedBeforeRoot, reply)
}

type OpeningArgs struct {
	Handle        string `json:"handle"`
	AssetID       string `json:"assetID"`
	Commitment    string `json:"commitment"`
	IssuanceNonce string `json:"issuanceNonce"`
}

func (a OpeningArgs) parse() (tx.AccountOpening, error) {
	handle, err := parseID(a.Handle, "handle")
	if err != nil {
		return tx.AccountOpening{}, err
	}
	assetID, err := parseID(a.AssetID, "assetID")
	if err != nil {
		return tx.AccountOpening{}, err
	}
	commitment, err := parseID(a.Commitment, "commitment")
	if err != nil {
		return tx.AccountOpening{}, err
	}
	nonce, err := parseID(a.IssuanceNonce, "issuanceNonce")
	if err != nil {
		return tx.AccountOpening{}, err
	}
	result := tx.AccountOpening{Handle: handle, AssetID: assetID,
		Commitment: commitment, IssuanceNonce: nonce}
	return result, result.Validate()
}

type IssueAccountArgs struct {
	Opening            OpeningArgs  `json:"opening"`
	Approval           ApprovalArgs `json:"approval"`
	ExpectedBeforeRoot string       `json:"expectedBeforeRoot"`
}

func (s *Server) IssueAccount(r *http.Request, args *IssueAccountArgs,
	reply *IssueTxReply) error {
	opening, err := args.Opening.parse()
	if err != nil {
		return err
	}
	approval, err := args.Approval.parse()
	if err != nil {
		return err
	}
	expectedBeforeRoot, err := parseID(args.ExpectedBeforeRoot, "expectedBeforeRoot")
	if err != nil {
		return err
	}
	if approval.BeforeRoot != expectedBeforeRoot {
		return fmt.Errorf("approval is bound to another state root")
	}
	return s.issue(r, &tx.Tx{Unsigned: &tx.OpenAccount{
		Opening: opening, Approval: approval}}, expectedBeforeRoot, reply)
}

type LegArgs struct {
	Handle           string `json:"handle"`
	AssetID          string `json:"assetID"`
	BeforeCommitment string `json:"beforeCommitment"`
	AfterCommitment  string `json:"afterCommitment"`
	BeforeSequence   uint64 `json:"beforeSequence"`
}

func (a LegArgs) parse() (tx.StateLeg, error) {
	handle, err := parseID(a.Handle, "handle")
	if err != nil {
		return tx.StateLeg{}, err
	}
	assetID, err := parseID(a.AssetID, "assetID")
	if err != nil {
		return tx.StateLeg{}, err
	}
	before, err := parseID(a.BeforeCommitment, "beforeCommitment")
	if err != nil {
		return tx.StateLeg{}, err
	}
	after, err := parseID(a.AfterCommitment, "afterCommitment")
	if err != nil {
		return tx.StateLeg{}, err
	}
	return tx.StateLeg{Handle: handle, AssetID: assetID,
		BeforeCommitment: before, AfterCommitment: after,
		BeforeSequence: a.BeforeSequence}, nil
}

type OrderArgs struct {
	OperationID              string    `json:"operationID"`
	Nullifier                string    `json:"nullifier"`
	Deadline                 uint64    `json:"deadline"`
	PaymentInstructionDigest string    `json:"paymentInstructionDigest"`
	ProofDigest              string    `json:"proofDigest"`
	MarketStatementDigest    string    `json:"marketStatementDigest"`
	Legs                     []LegArgs `json:"legs"`
}

func (a OrderArgs) parse() (tx.SettlementOrder, error) {
	operation, err := parseID(a.OperationID, "operationID")
	if err != nil {
		return tx.SettlementOrder{}, err
	}
	nullifier, err := parseID(a.Nullifier, "nullifier")
	if err != nil {
		return tx.SettlementOrder{}, err
	}
	payment, err := parseID(a.PaymentInstructionDigest, "paymentInstructionDigest")
	if err != nil {
		return tx.SettlementOrder{}, err
	}
	proof, err := parseID(a.ProofDigest, "proofDigest")
	if err != nil {
		return tx.SettlementOrder{}, err
	}
	market, err := parseID(a.MarketStatementDigest, "marketStatementDigest")
	if err != nil {
		return tx.SettlementOrder{}, err
	}
	if len(a.Legs) > tx.MaxLegs {
		return tx.SettlementOrder{}, fmt.Errorf("too many legs")
	}
	legs := make([]tx.StateLeg, len(a.Legs))
	for i, value := range a.Legs {
		legs[i], err = value.parse()
		if err != nil {
			return tx.SettlementOrder{}, fmt.Errorf("leg %d: %w", i, err)
		}
	}
	result := tx.SettlementOrder{OperationID: operation, Nullifier: nullifier,
		Deadline: a.Deadline, PaymentInstructionDigest: payment,
		ProofDigest: proof, MarketStatementDigest: market, Legs: legs}
	return result, result.Validate()
}

type IssueSettlementArgs struct {
	Order              OrderArgs    `json:"order"`
	Approval           ApprovalArgs `json:"approval"`
	ExpectedBeforeRoot string       `json:"expectedBeforeRoot"`
}

func (s *Server) IssueSettlement(r *http.Request, args *IssueSettlementArgs,
	reply *IssueTxReply) error {
	order, err := args.Order.parse()
	if err != nil {
		return err
	}
	approval, err := args.Approval.parse()
	if err != nil {
		return err
	}
	expectedBeforeRoot, err := parseID(args.ExpectedBeforeRoot, "expectedBeforeRoot")
	if err != nil {
		return err
	}
	if approval.BeforeRoot != expectedBeforeRoot {
		return fmt.Errorf("approval is bound to another state root")
	}
	return s.issue(r, &tx.Tx{Unsigned: &tx.Settle{
		Order: order, Approval: approval}}, expectedBeforeRoot, reply)
}

func (s *Server) issue(r *http.Request, transaction *tx.Tx,
	expectedBeforeRoot ids.ID, reply *IssueTxReply) error {
	txID, err := transaction.ID()
	if err != nil {
		return err
	}
	s.ctx.Lock.Lock()
	defer s.ctx.Lock.Unlock()
	if _, err := state.GetTransition(s.state, txID); err == nil {
		reply.TxID = txID
		return nil
	} else if !errors.Is(err, database.ErrNotFound) {
		return err
	}
	currentRoot, err := state.StateRoot(s.state)
	if err != nil {
		return err
	}
	if ids.ID(currentRoot) != expectedBeforeRoot {
		return fmt.Errorf("expected state root does not match current accepted state")
	}
	if err := s.builder.AddTx(r.Context(), transaction); err != nil {
		return err
	}
	if s.gossip == nil {
		return errors.New("transaction gossip is unavailable")
	}
	if err := s.gossip(r.Context(), transaction); err != nil {
		return fmt.Errorf("gossip transaction: %w", err)
	}
	reply.TxID = txID
	return nil
}

type TxStatusArgs struct {
	TxID ids.ID `json:"txID"`
}

type TxStatusReply struct {
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	TxID       ids.ID `json:"txID"`
	BlockID    ids.ID `json:"blockID,omitempty"`
	Height     uint64 `json:"height,omitempty"`
	Statement  string `json:"statement,omitempty"`
	BeforeRoot string `json:"beforeRoot,omitempty"`
	AfterRoot  string `json:"afterRoot,omitempty"`
}

func (s *Server) TxStatus(_ *http.Request, args *TxStatusArgs,
	reply *TxStatusReply) error {
	reply.TxID = args.TxID
	s.ctx.Lock.RLock()
	defer s.ctx.Lock.RUnlock()
	record, err := state.GetTransition(s.state, args.TxID)
	if err == nil {
		reply.Status = "accepted"
		reply.BlockID = record.BlockID
		reply.Height = record.Height
		reply.Statement = hex.EncodeToString(record.Statement[:])
		reply.BeforeRoot = hex.EncodeToString(record.BeforeRoot[:])
		reply.AfterRoot = hex.EncodeToString(record.AfterRoot[:])
		return nil
	}
	if !errors.Is(err, database.ErrNotFound) {
		return err
	}
	reply.Status, reply.Reason = s.builder.LookupTx(args.TxID)
	return nil
}

type LastAcceptedReply struct {
	BlockID    ids.ID `json:"blockID"`
	BlockBytes []byte `json:"blockBytes"`
}

func (s *Server) LastAccepted(_ *http.Request, _ *struct{},
	reply *LastAcceptedReply) error {
	s.ctx.Lock.RLock()
	reply.BlockID = s.chain.LastAccepted()
	s.ctx.Lock.RUnlock()
	bytes, err := state.GetBlock(s.state, reply.BlockID)
	reply.BlockBytes = bytes
	return err
}

func parseID(value, name string) (ids.ID, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ids.IDLen {
		return ids.Empty, fmt.Errorf("%s must be 32-byte lowercase or uppercase hex", name)
	}
	var id ids.ID
	copy(id[:], decoded)
	return id, nil
}
