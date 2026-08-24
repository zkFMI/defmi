package state

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ava-labs/avalanchego/database"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/shukob/defmi/avalanche/defmivm/genesis"
	"github.com/shukob/defmi/avalanche/defmivm/tx"
)

var (
	ErrUnknownAsset   = errors.New("unknown or inactive asset")
	ErrUnknownAccount = errors.New("unknown account")
	ErrAlreadyExists  = errors.New("state object already exists")
	ErrAlreadySettled = errors.New("settlement already applied")
	ErrCorruptState   = errors.New("corrupt DeFMI state")
	stateDomain       = []byte("QOMM:DEFMI:STATE:v1")
)

type AssetRecord struct {
	Definition tx.AssetDefinition
	Active     bool
}

func encodeAsset(record AssetRecord) ([]byte, error) {
	if err := record.Definition.Validate(); err != nil {
		return nil, err
	}
	code := []byte(record.Definition.Code)
	kind := []byte(record.Definition.Kind)
	value := make([]byte, 2+len(code)+1+len(kind)+1+32+1)
	binary.BigEndian.PutUint16(value[:2], uint16(len(code)))
	offset := 2
	copy(value[offset:], code)
	offset += len(code)
	value[offset] = byte(len(kind))
	offset++
	copy(value[offset:], kind)
	offset += len(kind)
	value[offset] = record.Definition.Decimals
	offset++
	copy(value[offset:], record.Definition.TermsDigest[:])
	offset += 32
	if record.Active {
		value[offset] = 1
	}
	return value, nil
}

func decodeAsset(assetID ids.ID, value []byte) (AssetRecord, error) {
	if len(value) < 2+1+1+32+1 {
		return AssetRecord{}, ErrCorruptState
	}
	codeLen := int(binary.BigEndian.Uint16(value[:2]))
	offset := 2
	if codeLen == 0 || offset+codeLen+1 > len(value) {
		return AssetRecord{}, ErrCorruptState
	}
	code := string(value[offset : offset+codeLen])
	offset += codeLen
	kindLen := int(value[offset])
	offset++
	if kindLen == 0 || offset+kindLen+1+32+1 != len(value) {
		return AssetRecord{}, ErrCorruptState
	}
	kind := string(value[offset : offset+kindLen])
	offset += kindLen
	decimals := value[offset]
	offset++
	var terms ids.ID
	copy(terms[:], value[offset:offset+32])
	offset += 32
	if value[offset] > 1 {
		return AssetRecord{}, ErrCorruptState
	}
	record := AssetRecord{
		Definition: tx.AssetDefinition{AssetID: assetID, Code: code, Kind: kind,
			Decimals: decimals, TermsDigest: terms},
		Active: value[offset] == 1,
	}
	if err := record.Definition.Validate(); err != nil {
		return AssetRecord{}, fmt.Errorf("%w: %v", ErrCorruptState, err)
	}
	return record, nil
}

func GetAsset(db database.KeyValueReader, assetID ids.ID) (AssetRecord, error) {
	value, err := db.Get(flatten(assetPrefix, assetID[:]))
	if errors.Is(err, database.ErrNotFound) {
		return AssetRecord{}, ErrUnknownAsset
	}
	if err != nil {
		return AssetRecord{}, err
	}
	return decodeAsset(assetID, value)
}

func AddAsset(db database.KeyValueReaderWriter, asset tx.AssetDefinition) error {
	key := flatten(assetPrefix, asset.AssetID[:])
	exists, err := db.Has(key)
	if err != nil {
		return err
	}
	if exists {
		return ErrAlreadyExists
	}
	value, err := encodeAsset(AssetRecord{Definition: asset, Active: true})
	if err != nil {
		return err
	}
	return db.Put(key, value)
}

type AccountRecord struct {
	AssetID    ids.ID
	Commitment ids.ID
	Sequence   uint64
}

func encodeAccount(record AccountRecord) []byte {
	value := make([]byte, 72)
	copy(value[:32], record.AssetID[:])
	copy(value[32:64], record.Commitment[:])
	binary.BigEndian.PutUint64(value[64:], record.Sequence)
	return value
}

func decodeAccount(value []byte) (AccountRecord, error) {
	if len(value) != 72 {
		return AccountRecord{}, ErrCorruptState
	}
	var result AccountRecord
	copy(result.AssetID[:], value[:32])
	copy(result.Commitment[:], value[32:64])
	result.Sequence = binary.BigEndian.Uint64(value[64:])
	return result, nil
}

func GetAccount(db database.KeyValueReader, handle ids.ID) (AccountRecord, error) {
	value, err := db.Get(flatten(accountPrefix, handle[:]))
	if errors.Is(err, database.ErrNotFound) {
		return AccountRecord{}, ErrUnknownAccount
	}
	if err != nil {
		return AccountRecord{}, err
	}
	return decodeAccount(value)
}

func AddAccount(db database.KeyValueReaderWriter, opening tx.AccountOpening) error {
	key := flatten(accountPrefix, opening.Handle[:])
	exists, err := db.Has(key)
	if err != nil {
		return err
	}
	if exists {
		return ErrAlreadyExists
	}
	asset, err := GetAsset(db, opening.AssetID)
	if err != nil {
		return err
	}
	if !asset.Active {
		return ErrUnknownAsset
	}
	return db.Put(key, encodeAccount(AccountRecord{
		AssetID: opening.AssetID, Commitment: opening.Commitment,
	}))
}

func SetAccount(db database.KeyValueWriter, handle ids.ID, record AccountRecord) error {
	return db.Put(flatten(accountPrefix, handle[:]), encodeAccount(record))
}

func HasNullifier(db database.KeyValueReader, nullifier ids.ID) (bool, error) {
	return db.Has(flatten(nullifierPrefix, nullifier[:]))
}

func AddNullifier(db database.KeyValueWriter, nullifier ids.ID, deadline uint64,
	statement ids.ID) error {
	value := make([]byte, 40)
	binary.BigEndian.PutUint64(value[:8], deadline)
	copy(value[8:], statement[:])
	return db.Put(flatten(nullifierPrefix, nullifier[:]), value)
}

func HasOperation(db database.KeyValueReader, operation ids.ID) (bool, error) {
	return db.Has(flatten(operationPrefix, operation[:]))
}

func AddOperation(db database.KeyValueWriter, operation, statement ids.ID) error {
	return db.Put(flatten(operationPrefix, operation[:]), statement[:])
}

type TransitionRecord struct {
	Statement  ids.ID
	BeforeRoot ids.ID
	AfterRoot  ids.ID
	BlockID    ids.ID
	Height     uint64
}

func encodeTransition(record TransitionRecord) []byte {
	value := make([]byte, 136)
	copy(value[:32], record.Statement[:])
	copy(value[32:64], record.BeforeRoot[:])
	copy(value[64:96], record.AfterRoot[:])
	copy(value[96:128], record.BlockID[:])
	binary.BigEndian.PutUint64(value[128:], record.Height)
	return value
}

func decodeTransition(value []byte) (TransitionRecord, error) {
	if len(value) != 136 {
		return TransitionRecord{}, ErrCorruptState
	}
	var record TransitionRecord
	copy(record.Statement[:], value[:32])
	copy(record.BeforeRoot[:], value[32:64])
	copy(record.AfterRoot[:], value[64:96])
	copy(record.BlockID[:], value[96:128])
	record.Height = binary.BigEndian.Uint64(value[128:])
	return record, nil
}

func SetTransition(db database.KeyValueWriter, txID ids.ID,
	record TransitionRecord) error {
	return db.Put(flatten(transitionPrefix, txID[:]), encodeTransition(record))
}

func GetTransition(db database.KeyValueReader, txID ids.ID) (TransitionRecord, error) {
	value, err := db.Get(flatten(transitionPrefix, txID[:]))
	if err != nil {
		return TransitionRecord{}, err
	}
	return decodeTransition(value)
}

func FinalizeTransition(db database.KeyValueReaderWriter, txID, blockID ids.ID,
	height uint64) error {
	record, err := GetTransition(db, txID)
	if err != nil {
		return err
	}
	record.BlockID = blockID
	record.Height = height
	return SetTransition(db, txID, record)
}

func PutGenesis(db database.KeyValueWriter, g *genesis.Genesis) error {
	bytes, err := genesis.Marshal(g)
	if err != nil {
		return err
	}
	return db.Put(configKey, bytes)
}

func GetGenesis(db database.KeyValueReader) (*genesis.Genesis, error) {
	bytes, err := db.Get(configKey)
	if err != nil {
		return nil, err
	}
	return genesis.Parse(bytes)
}

func StateRoot(db database.Database) (ids.ID, error) {
	hash := sha256.New()
	_, _ = hash.Write(stateDomain)

	assets := db.NewIteratorWithPrefix(assetPrefix)
	for assets.Next() {
		key := assets.Key()
		if len(key) != len(assetPrefix)+ids.IDLen {
			assets.Release()
			return ids.Empty, ErrCorruptState
		}
		var assetID ids.ID
		copy(assetID[:], key[len(assetPrefix):])
		record, err := decodeAsset(assetID, assets.Value())
		if err != nil {
			assets.Release()
			return ids.Empty, err
		}
		row, err := json.Marshal([]any{
			hexID(assetID), record.Definition.Code, record.Definition.Kind,
			int(record.Definition.Decimals), hexID(record.Definition.TermsDigest),
			boolInt(record.Active),
		})
		if err != nil {
			assets.Release()
			return ids.Empty, err
		}
		_, _ = hash.Write(row)
	}
	if err := assets.Error(); err != nil {
		assets.Release()
		return ids.Empty, err
	}
	assets.Release()

	accounts := db.NewIteratorWithPrefix(accountPrefix)
	for accounts.Next() {
		key := accounts.Key()
		if len(key) != len(accountPrefix)+ids.IDLen {
			accounts.Release()
			return ids.Empty, ErrCorruptState
		}
		record, err := decodeAccount(accounts.Value())
		if err != nil {
			accounts.Release()
			return ids.Empty, err
		}
		_, _ = hash.Write(key[len(accountPrefix):])
		_, _ = hash.Write(record.AssetID[:])
		_, _ = hash.Write(record.Commitment[:])
		var sequence [8]byte
		binary.BigEndian.PutUint64(sequence[:], record.Sequence)
		_, _ = hash.Write(sequence[:])
	}
	if err := accounts.Error(); err != nil {
		accounts.Release()
		return ids.Empty, err
	}
	accounts.Release()

	nullifiers := db.NewIteratorWithPrefix(nullifierPrefix)
	for nullifiers.Next() {
		key := nullifiers.Key()
		value := nullifiers.Value()
		if len(key) != len(nullifierPrefix)+ids.IDLen || len(value) != 40 {
			nullifiers.Release()
			return ids.Empty, ErrCorruptState
		}
		_, _ = hash.Write(key[len(nullifierPrefix):])
		_, _ = hash.Write(value)
	}
	if err := nullifiers.Error(); err != nil {
		nullifiers.Release()
		return ids.Empty, err
	}
	nullifiers.Release()

	var result ids.ID
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func hexID(value ids.ID) string { return fmt.Sprintf("%x", value[:]) }
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
