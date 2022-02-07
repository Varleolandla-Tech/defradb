// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package core

import (
	cid "github.com/ipfs/go-cid"
)

// Delta represents a delta-state update to delta-CRDT
// They are serialized to and from Protobuf (or CBOR)
type Delta interface {
	GetPriority() uint64
	SetPriority(uint64)
	Marshal() ([]byte, error)
	Value() interface{}
}

type CompositeDelta interface {
	Delta
	Links() []DAGLink
}

type NetDelta interface {
	Delta
	GetSchemaID() string
	// DocKey() key.DocKey
}

type DAGLink struct {
	Name string
	Cid  cid.Cid
}
