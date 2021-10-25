// Copyright 2020 Source Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.
package crdt

import (
	// "time"

	"bytes"

	"github.com/pkg/errors"

	"github.com/sourcenetwork/defradb/core"

	ipld "github.com/ipfs/go-ipld-format"
	dag "github.com/ipfs/go-merkledag"

	"github.com/ugorji/go/codec"
)

var (
	// ensure types implements core interfaces
	_ core.ReplicatedData = (*LWWRegister)(nil)
	_ core.Delta          = (*LWWRegDelta)(nil)
)

// LWWRegDelta is a single delta operation for an LWWRegister
// TODO: Expand delta metadata (investigate if needed)
type LWWRegDelta struct {
	Priority uint64
	Data     []byte
}

// GetPriority gets the current priority for this delta
func (delta *LWWRegDelta) GetPriority() uint64 {
	return delta.Priority
}

// SetPriority will set the priority for this delta
func (delta *LWWRegDelta) SetPriority(prio uint64) {
	delta.Priority = prio
}

// Marshal encodes the delta using CBOR
// for now lets do cbor (quick to implement)
func (delta *LWWRegDelta) Marshal() ([]byte, error) {
	h := &codec.CborHandle{}
	buf := bytes.NewBuffer(nil)
	enc := codec.NewEncoder(buf, h)
	err := enc.Encode(struct {
		Priority uint64
		Data     []byte
	}{delta.Priority, delta.Data})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (delta *LWWRegDelta) Value() interface{} {
	return delta.Data
}

// LWWRegister Last-Writer-Wins Register
// a simple CRDT type that allows set/get of an
// arbitrary data type that ensures convergence
type LWWRegister struct {
	baseCRDT
	data []byte
}

// NewLWWRegister returns a new instance of the LWWReg with the given ID
func NewLWWRegister(store core.DSReaderWriter, key core.DataStoreKey) LWWRegister {
	return LWWRegister{
		baseCRDT: newBaseCRDT(store, key),
		// id:    id,
		// data:  data,
		// ts:    ts,
		// clock: clock,
	}
}

// Value gets the current register value
// RETURN STATE
func (reg LWWRegister) Value() ([]byte, error) {
	valueK := reg.key.WithValueFlag()
	buf, err := reg.store.Get(valueK.ToDS())
	if err != nil {
		return nil, err
	}
	// ignore the first byte (CRDT Type marker) from the returned value
	buf = buf[1:]
	return buf, nil
}

// Set generates a new delta with the supplied value
// RETURN DELTA
func (reg LWWRegister) Set(value []byte) *LWWRegDelta {
	// return NewLWWRegister(reg.id, value, reg.clock.Apply(), reg.clock)
	return &LWWRegDelta{
		Data: value,
	}
}

// RETURN DELTA
// func (reg LWWRegister) setWithClock(value []byte, clock Clock) LWWRegDelta {
// 	// return NewLWWRegister(reg.id, value, clock.Apply(), clock)
// 	return LWWRegDelta{
// 		data: value,
// 	}
// }

// Merge implements ReplicatedData interface
// Merge two LWWRegisty based on the order of the timestamp (ts),
// if they are equal, compare IDs
// MUTATE STATE
func (reg LWWRegister) Merge(delta core.Delta, id string) error {
	d, ok := delta.(*LWWRegDelta)
	if !ok {
		return core.ErrMismatchedMergeType
	}

	return reg.setValue(d.Data, d.GetPriority())
}

func (reg LWWRegister) setValue(val []byte, priority uint64) error {
	curPrio, err := reg.getPriority(reg.key.WithPriorityFlag())
	if err != nil {
		return errors.Wrap(err, "Failed to get priority for Set")
	}

	// if the current priority is higher ignore put
	// else if the current value is lexographically
	// greater than the new then ignore
	valueK := reg.key.WithValueFlag()
	if priority < curPrio {
		return nil
	} else if priority == curPrio {
		curValue, _ := reg.store.Get(valueK.ToDS())
		if bytes.Compare(curValue, val) >= 0 {
			return nil
		}
	}

	// prepend the value byte array with a single byte indicator for the CRDT Type.
	buf := append([]byte{byte(core.LWW_REGISTER)}, val...)
	err = reg.store.Put(valueK.ToDS(), buf)
	if err != nil {
		return errors.Wrap(err, "Failed to store new value")
	}

	return reg.setPriority(reg.key, priority)
}

// DeltaDecode is a typed helper to extract
// a LWWRegDelta from a ipld.Node
// for now lets do cbor (quick to implement)
func (reg LWWRegister) DeltaDecode(node ipld.Node) (core.Delta, error) {
	delta := &LWWRegDelta{}
	pbNode, ok := node.(*dag.ProtoNode)
	if !ok {
		return nil, errors.New("Failed to cast ipld.Node to ProtoNode")
	}
	data := pbNode.Data()
	// fmt.Println(data)
	h := &codec.CborHandle{}
	dec := codec.NewDecoderBytes(data, h)
	err := dec.Decode(delta)
	if err != nil {
		return nil, err
	}
	return delta, nil
}
