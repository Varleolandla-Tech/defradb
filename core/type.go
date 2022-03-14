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

// CType indicates CRDT type
type CType byte

const (
	//no lint
	NONE_CRDT = CType(iota) // reserved none type
	LWW_REGISTER
	OBJECT
	COMPOSITE
)

const (
	COMPOSITE_NAMESPACE = "C"
	HEAD                = "_head"
)
