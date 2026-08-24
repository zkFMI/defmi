package tx

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ava-labs/avalanchego/ids"
)

const (
	assetDomain      = "QOMM:DEFMI:ASSET:v1"
	accountDomain    = "QOMM:DEFMI:ACCOUNT:v1"
	settlementDomain = "QOMM:DEFMI:SETTLEMENT:v1"
)

func hexID(value ids.ID) string { return hex.EncodeToString(value[:]) }

func canonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}
	return encoded, nil
}

func (a AssetDefinition) Statement() (ids.ID, error) {
	if err := a.Validate(); err != nil {
		return ids.Empty, err
	}
	body, err := canonical(map[string]any{
		"asset_id":     hexID(a.AssetID),
		"code":         a.Code,
		"kind":         a.Kind,
		"decimals":     a.Decimals,
		"terms_digest": hexID(a.TermsDigest),
	})
	if err != nil {
		return ids.Empty, err
	}
	return digest(assetDomain, body), nil
}

func (o AccountOpening) Statement() (ids.ID, error) {
	if err := o.Validate(); err != nil {
		return ids.Empty, err
	}
	body, err := canonical(map[string]any{
		"handle":         hexID(o.Handle),
		"asset_id":       hexID(o.AssetID),
		"commitment":     hexID(o.Commitment),
		"issuance_nonce": hexID(o.IssuanceNonce),
	})
	if err != nil {
		return ids.Empty, err
	}
	return digest(accountDomain, body), nil
}

func (o SettlementOrder) Statement() (ids.ID, error) {
	if err := o.Validate(); err != nil {
		return ids.Empty, err
	}
	legs := make([]map[string]any, len(o.Legs))
	for i, leg := range o.Legs {
		legs[i] = map[string]any{
			"handle":            hexID(leg.Handle),
			"asset_id":          hexID(leg.AssetID),
			"before_commitment": hexID(leg.BeforeCommitment),
			"after_commitment":  hexID(leg.AfterCommitment),
			"before_sequence":   leg.BeforeSequence,
		}
	}
	body, err := canonical(map[string]any{
		"operation_id":               hexID(o.OperationID),
		"nullifier":                  hexID(o.Nullifier),
		"deadline":                   o.Deadline,
		"payment_instruction_digest": hexID(o.PaymentInstructionDigest),
		"proof_digest":               hexID(o.ProofDigest),
		"market_statement_digest":    hexID(o.MarketStatementDigest),
		"legs":                       legs,
	})
	if err != nil {
		return ids.Empty, err
	}
	return digest(settlementDomain, body), nil
}
