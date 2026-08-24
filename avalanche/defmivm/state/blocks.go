// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See THIRD_PARTY_NOTICES.md for the adapted XSVM source and license.

package state

import (
	"github.com/ava-labs/avalanchego/database"
	"github.com/ava-labs/avalanchego/ids"
)

func IsInitialized(db database.KeyValueReader) (bool, error) {
	return db.Has(initializedKey)
}

func SetInitialized(db database.KeyValueWriter) error { return db.Put(initializedKey, nil) }

func GetLastAccepted(db database.KeyValueReader) (ids.ID, error) {
	return database.GetID(db, blockPrefix)
}

func SetLastAccepted(db database.KeyValueWriter, blkID ids.ID) error {
	return database.PutID(db, blockPrefix, blkID)
}

func GetBlockIDByHeight(db database.KeyValueReader, height uint64) (ids.ID, error) {
	return database.GetID(db, flatten(blockPrefix, database.PackUInt64(height)))
}

func GetBlock(db database.KeyValueReader, blkID ids.ID) ([]byte, error) {
	return db.Get(flatten(blockPrefix, blkID[:]))
}

func AddBlock(db database.KeyValueWriter, height uint64, blkID ids.ID,
	bytes []byte) error {
	if err := database.PutID(db,
		flatten(blockPrefix, database.PackUInt64(height)), blkID); err != nil {
		return err
	}
	return db.Put(flatten(blockPrefix, blkID[:]), bytes)
}
