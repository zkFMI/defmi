// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See THIRD_PARTY_NOTICES.md for the adapted XSVM source and license.

package defmivm

import (
	"github.com/ava-labs/avalanchego/utils/logging"
	"github.com/ava-labs/avalanchego/vms"
)

var _ vms.Factory = (*Factory)(nil)

type Factory struct{}

func (*Factory) New(logging.Logger) (interface{}, error) { return &VM{}, nil }
