package tx

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/hashing"
)

const (
	MaxCommittee = 64
	MaxApprovals = 64
	MaxLegs      = 32
	MaxCodeBytes = 64
	MaxNodeIDLen = 128
	MaxDomainLen = 128
)

var (
	approvalDomain = []byte("QOMM:DEFMI:FACILITY:v2")
	codePattern    = regexp.MustCompile(`^[A-Za-z0-9._:/+-]{1,64}$`)
	nodePattern    = regexp.MustCompile(`^[A-Za-z0-9._:/+-]{1,128}$`)
	domainPattern  = regexp.MustCompile(`^[A-Za-z0-9._:/+-]{1,128}$`)

	ErrInvalidTransition = errors.New("invalid DeFMI transition")
)

type CommitteeMember struct {
	NodeID    string                      `serialize:"true" json:"nodeID"`
	PublicKey [ed25519.PublicKeySize]byte `serialize:"true" json:"publicKey"`
}

type Committee struct {
	Epoch     uint64            `serialize:"true" json:"epoch"`
	Threshold uint16            `serialize:"true" json:"threshold"`
	Members   []CommitteeMember `serialize:"true" json:"members"`
}

func (c Committee) Validate() error {
	if c.Epoch == 0 || c.Threshold == 0 || int(c.Threshold) > len(c.Members) ||
		len(c.Members) == 0 || len(c.Members) > MaxCommittee {
		return fmt.Errorf("%w: invalid committee dimensions", ErrInvalidTransition)
	}
	seen := make(map[string]struct{}, len(c.Members))
	seenKeys := make(map[[ed25519.PublicKeySize]byte]struct{}, len(c.Members))
	var zeroKey [ed25519.PublicKeySize]byte
	for _, member := range c.Members {
		if len(member.NodeID) > MaxNodeIDLen || !nodePattern.MatchString(member.NodeID) {
			return fmt.Errorf("%w: invalid committee node identifier", ErrInvalidTransition)
		}
		if _, ok := seen[member.NodeID]; ok {
			return fmt.Errorf("%w: duplicate committee node", ErrInvalidTransition)
		}
		seen[member.NodeID] = struct{}{}
		if member.PublicKey == zeroKey {
			return fmt.Errorf("%w: empty committee public key", ErrInvalidTransition)
		}
		if _, ok := seenKeys[member.PublicKey]; ok {
			return fmt.Errorf("%w: duplicate committee public key", ErrInvalidTransition)
		}
		seenKeys[member.PublicKey] = struct{}{}
	}
	return nil
}

func (c Committee) PublicKeys() map[string]ed25519.PublicKey {
	result := make(map[string]ed25519.PublicKey, len(c.Members))
	for _, member := range c.Members {
		key := make([]byte, ed25519.PublicKeySize)
		copy(key, member.PublicKey[:])
		result[member.NodeID] = ed25519.PublicKey(key)
	}
	return result
}

type NodeApproval struct {
	NodeID    string                      `serialize:"true" json:"nodeID"`
	Signature [ed25519.SignatureSize]byte `serialize:"true" json:"signature"`
}

type QuorumApproval struct {
	Statement   ids.ID         `serialize:"true" json:"statement"`
	SignerEpoch uint64         `serialize:"true" json:"signerEpoch"`
	Domain      string         `serialize:"true" json:"domain"`
	BeforeRoot  ids.ID         `serialize:"true" json:"beforeRoot"`
	Approvals   []NodeApproval `serialize:"true" json:"approvals"`
}

func approvalMessage(epoch uint64, domain string, beforeRoot, statement ids.ID) []byte {
	message := make([]byte, 0, len(approvalDomain)+8+2+len(domain)+2*ids.IDLen)
	message = append(message, approvalDomain...)
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], epoch)
	message = append(message, encoded[:]...)
	var domainLen [2]byte
	binary.BigEndian.PutUint16(domainLen[:], uint16(len(domain)))
	message = append(message, domainLen[:]...)
	message = append(message, domain...)
	message = append(message, beforeRoot[:]...)
	return append(message, statement[:]...)
}

func (a QuorumApproval) Verify(committee Committee, domain string,
	beforeRoot, expected ids.ID) error {
	if err := committee.Validate(); err != nil {
		return err
	}
	if !domainPattern.MatchString(domain) || a.Domain != domain ||
		a.BeforeRoot != beforeRoot || a.Statement != expected ||
		a.SignerEpoch != committee.Epoch ||
		len(a.Approvals) > MaxApprovals {
		return fmt.Errorf("%w: approval context, statement or epoch mismatch", ErrInvalidTransition)
	}
	keys := committee.PublicKeys()
	seen := make(map[string]struct{}, len(a.Approvals))
	valid := 0
	message := approvalMessage(committee.Epoch, domain, beforeRoot, expected)
	for _, approval := range a.Approvals {
		if _, duplicate := seen[approval.NodeID]; duplicate {
			continue
		}
		seen[approval.NodeID] = struct{}{}
		key, known := keys[approval.NodeID]
		if known && ed25519.Verify(key, message, approval.Signature[:]) {
			valid++
		}
	}
	if valid < int(committee.Threshold) {
		return fmt.Errorf("%w: approval threshold not met", ErrInvalidTransition)
	}
	return nil
}

type AssetDefinition struct {
	AssetID     ids.ID `serialize:"true" json:"assetID"`
	Code        string `serialize:"true" json:"code"`
	Kind        string `serialize:"true" json:"kind"`
	Decimals    uint8  `serialize:"true" json:"decimals"`
	TermsDigest ids.ID `serialize:"true" json:"termsDigest"`
}

func (a AssetDefinition) Validate() error {
	if a.AssetID == ids.Empty || a.TermsDigest == ids.Empty ||
		!codePattern.MatchString(a.Code) || a.Decimals > 30 {
		return fmt.Errorf("%w: asset code or decimals", ErrInvalidTransition)
	}
	switch a.Kind {
	case "cash", "security", "fund", "commodity", "carbon", "other":
		return nil
	default:
		return fmt.Errorf("%w: unknown asset kind", ErrInvalidTransition)
	}
}

type AccountOpening struct {
	Handle        ids.ID `serialize:"true" json:"handle"`
	AssetID       ids.ID `serialize:"true" json:"assetID"`
	Commitment    ids.ID `serialize:"true" json:"commitment"`
	IssuanceNonce ids.ID `serialize:"true" json:"issuanceNonce"`
}

func (o AccountOpening) Validate() error {
	if o.Handle == ids.Empty || o.AssetID == ids.Empty ||
		o.Commitment == ids.Empty || o.IssuanceNonce == ids.Empty {
		return fmt.Errorf("%w: empty account field", ErrInvalidTransition)
	}
	return nil
}

type StateLeg struct {
	Handle           ids.ID `serialize:"true" json:"handle"`
	AssetID          ids.ID `serialize:"true" json:"assetID"`
	BeforeCommitment ids.ID `serialize:"true" json:"beforeCommitment"`
	AfterCommitment  ids.ID `serialize:"true" json:"afterCommitment"`
	BeforeSequence   uint64 `serialize:"true" json:"beforeSequence"`
}

type SettlementOrder struct {
	OperationID              ids.ID     `serialize:"true" json:"operationID"`
	Nullifier                ids.ID     `serialize:"true" json:"nullifier"`
	Deadline                 uint64     `serialize:"true" json:"deadline"`
	PaymentInstructionDigest ids.ID     `serialize:"true" json:"paymentInstructionDigest"`
	ProofDigest              ids.ID     `serialize:"true" json:"proofDigest"`
	MarketStatementDigest    ids.ID     `serialize:"true" json:"marketStatementDigest"`
	Legs                     []StateLeg `serialize:"true" json:"legs"`
}

func (o SettlementOrder) Validate() error {
	if o.OperationID == ids.Empty || o.Nullifier == ids.Empty ||
		o.PaymentInstructionDigest == ids.Empty || o.ProofDigest == ids.Empty ||
		o.MarketStatementDigest == ids.Empty || o.Deadline == 0 ||
		len(o.Legs) == 0 || len(o.Legs) > MaxLegs {
		return fmt.Errorf("%w: settlement dimensions", ErrInvalidTransition)
	}
	seen := make(map[ids.ID]struct{}, len(o.Legs))
	for _, leg := range o.Legs {
		if leg.Handle == ids.Empty || leg.AssetID == ids.Empty ||
			leg.BeforeCommitment == ids.Empty || leg.AfterCommitment == ids.Empty {
			return fmt.Errorf("%w: empty settlement leg field", ErrInvalidTransition)
		}
		if _, duplicate := seen[leg.Handle]; duplicate {
			return fmt.Errorf("%w: duplicate settlement handle", ErrInvalidTransition)
		}
		seen[leg.Handle] = struct{}{}
	}
	return nil
}

type Unsigned interface {
	Visit(Visitor) error
	Statement() (ids.ID, error)
}

type Visitor interface {
	RegisterAsset(*RegisterAsset) error
	OpenAccount(*OpenAccount) error
	Settle(*Settle) error
}

type RegisterAsset struct {
	Asset    AssetDefinition `serialize:"true" json:"asset"`
	Approval QuorumApproval  `serialize:"true" json:"approval"`
}

func (a *RegisterAsset) Visit(v Visitor) error      { return v.RegisterAsset(a) }
func (a *RegisterAsset) Statement() (ids.ID, error) { return a.Asset.Statement() }

type OpenAccount struct {
	Opening  AccountOpening `serialize:"true" json:"opening"`
	Approval QuorumApproval `serialize:"true" json:"approval"`
}

func (a *OpenAccount) Visit(v Visitor) error      { return v.OpenAccount(a) }
func (a *OpenAccount) Statement() (ids.ID, error) { return a.Opening.Statement() }

type Settle struct {
	Order    SettlementOrder `serialize:"true" json:"order"`
	Approval QuorumApproval  `serialize:"true" json:"approval"`
}

func (s *Settle) Visit(v Visitor) error      { return v.Settle(s) }
func (s *Settle) Statement() (ids.ID, error) { return s.Order.Statement() }

type Tx struct {
	Unsigned Unsigned `serialize:"true" json:"unsigned"`
}

func Parse(bytes []byte) (*Tx, error) {
	parsed := &Tx{}
	_, err := Codec.Unmarshal(bytes, parsed)
	return parsed, err
}

func (t *Tx) Bytes() ([]byte, error) {
	return Codec.Marshal(CodecVersion, t)
}

func (t *Tx) ID() (ids.ID, error) {
	bytes, err := t.Bytes()
	return hashing.ComputeHash256Array(bytes), err
}

func NewApproval(statement, beforeRoot ids.ID, domain string, committee Committee,
	privateKeys map[string]ed25519.PrivateKey) QuorumApproval {
	nodes := make([]string, 0, len(privateKeys))
	for node := range privateKeys {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	message := approvalMessage(committee.Epoch, domain, beforeRoot, statement)
	approvals := make([]NodeApproval, 0, len(nodes))
	for _, node := range nodes {
		var signature [ed25519.SignatureSize]byte
		copy(signature[:], ed25519.Sign(privateKeys[node], message))
		approvals = append(approvals, NodeApproval{NodeID: node, Signature: signature})
	}
	return QuorumApproval{Statement: statement, SignerEpoch: committee.Epoch,
		Domain: domain, BeforeRoot: beforeRoot,
		Approvals: approvals}
}

func digest(domain string, canonical []byte) ids.ID {
	bytes := append([]byte(domain), canonical...)
	return ids.ID(sha256.Sum256(bytes))
}
