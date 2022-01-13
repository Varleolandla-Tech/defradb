// Copyright 2020 Source Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.
package planner

import (
	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/query/graphql/parser"
)

// Limit the results, yielding only what the limit/offset permits
// @todo: Handle cursor
type hardLimitNode struct {
	p    *Planner
	plan planNode

	limit    int64
	offset   int64
	rowIndex int64
}

// HardLimit creates a new hardLimitNode initalized from
// the parser.Limit object.
func (p *Planner) HardLimit(n *parser.Limit) (*hardLimitNode, error) {
	if n == nil {
		return nil, nil // nothing to do
	}
	return &hardLimitNode{
		p:        p,
		limit:    n.Limit,
		offset:   n.Offset,
		rowIndex: 0,
	}, nil
}

func (n *hardLimitNode) Init() error {
	n.rowIndex = 0
	return n.plan.Init()
}

func (n *hardLimitNode) Start() error                   { return n.plan.Start() }
func (n *hardLimitNode) Spans(spans core.Spans)         { n.plan.Spans(spans) }
func (n *hardLimitNode) Close() error                   { return n.plan.Close() }
func (n *hardLimitNode) Values() map[string]interface{} { return n.plan.Values() }

func (n *hardLimitNode) Next() (bool, error) {
	// check if we're passed the limit
	if n.rowIndex-n.offset >= n.limit {
		return false, nil
	}

	for {
		// get next
		if next, err := n.plan.Next(); !next {
			return false, err
		}

		// check if we're beyond the offset
		n.rowIndex++
		if n.rowIndex > n.offset {
			break
		}
	}

	return true, nil
}

func (n *hardLimitNode) Source() planNode { return n.plan }

// limit the results, flagging any records outside the bounds of limit/offset with
// with a 'hidden' flag blocking rendering.  Used if consumers of the results require
// the full dataset.
type renderLimitNode struct {
	p    *Planner
	plan planNode

	limit    int64
	offset   int64
	rowIndex int64
}

// RenderLimit creates a new renderLimitNode initalized from
// the parser.Limit object.
func (p *Planner) RenderLimit(n *parser.Limit) (*renderLimitNode, error) {
	if n == nil {
		return nil, nil // nothing to do
	}
	return &renderLimitNode{
		p:        p,
		limit:    n.Limit,
		offset:   n.Offset,
		rowIndex: 0,
	}, nil
}

func (n *renderLimitNode) Init() error {
	n.rowIndex = 0
	return n.plan.Init()
}

func (n *renderLimitNode) Start() error           { return n.plan.Start() }
func (n *renderLimitNode) Spans(spans core.Spans) { n.plan.Spans(spans) }
func (n *renderLimitNode) Close() error           { return n.plan.Close() }
func (n *renderLimitNode) Values() map[string]interface{} {
	value := n.plan.Values()

	if n.rowIndex-n.offset > n.limit || n.rowIndex <= n.offset {
		value[parser.HiddenFieldName] = struct{}{}
	}

	return value
}

func (n *renderLimitNode) Next() (bool, error) {
	if next, err := n.plan.Next(); !next {
		return false, err
	}

	n.rowIndex++
	return true, nil
}

func (n *renderLimitNode) Source() planNode { return n.plan }
