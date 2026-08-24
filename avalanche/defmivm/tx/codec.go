// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See THIRD_PARTY_NOTICES.md for the adapted XSVM source and license.

package tx

import (
	"errors"
	"math"

	"github.com/ava-labs/avalanchego/codec"
	"github.com/ava-labs/avalanchego/codec/linearcodec"
)

const CodecVersion = 0

var Codec codec.Manager

func init() {
	c := linearcodec.NewDefault()
	Codec = codec.NewManager(math.MaxInt32)
	if err := errors.Join(
		c.RegisterType(&RegisterAsset{}),
		c.RegisterType(&OpenAccount{}),
		c.RegisterType(&Settle{}),
		Codec.RegisterCodec(CodecVersion, c),
	); err != nil {
		panic(err)
	}
}
