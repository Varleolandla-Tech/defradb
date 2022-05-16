// Copyright 2022 Democratized Data Foundation
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
	"encoding/json"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/db/base"
	"github.com/sourcenetwork/defradb/query/graphql/parser"
)

type updateNode struct {
	documentIterator

	p *Planner

	collection client.Collection

	filter *parser.Filter
	ids    []string

	patch string

	isUpdating bool
	updateIter *valuesNode

	results planNode
}

// Next only returns once.
func (n *updateNode) Next() (bool, error) {
	// if err := n.collection.WithTxn(n.p.txn).Create(n.doc); err != nil {
	// 	return false, err
	// }

	if n.isUpdating {
		// create our result values node
		if n.updateIter == nil {
			vnode := n.p.newContainerValuesNode(nil)
			n.updateIter = vnode
		}

		// apply the updates
		// @todo: handle filter vs ID based
		var results *client.UpdateResult
		var err error
		numids := len(n.ids)
		if numids == 1 {
			key, err2 := client.NewDocKeyFromString(n.ids[0])
			if err2 != nil {
				return false, err2
			}
			results, err = n.collection.UpdateWithKey(n.p.ctx, key, n.patch)
		} else if numids > 1 {
			// todo
			keys := make([]client.DocKey, len(n.ids))
			for i, v := range n.ids {
				keys[i], err = client.NewDocKeyFromString(v)
				if err != nil {
					return false, err
				}
			}
			results, err = n.collection.UpdateWithKeys(n.p.ctx, keys, n.patch)
		} else {
			results, err = n.collection.UpdateWithFilter(n.p.ctx, n.filter, n.patch)
		}

		if err != nil {
			return false, err
		}

		// consume the updates into our valuesNode
		for _, resKey := range results.DocKeys {
			err := n.updateIter.docs.AddDoc(core.Doc{"_key": resKey})
			if err != nil {
				return false, err
			}
		}
		n.isUpdating = false

		// lets release the results dockeys slice memory
		results.DocKeys = nil
	}

	hasNext, err := n.updateIter.Next()
	if err != nil || !hasNext {
		return hasNext, err
	}

	updatedDoc := n.updateIter.Value()
	// create a new span with the updateDoc._key
	docKeyStr := updatedDoc["_key"].(string)
	desc := n.collection.Description()
	updatedDocKeyIndex := base.MakeDocKey(desc, docKeyStr)
	spans := core.Spans{core.NewSpan(updatedDocKeyIndex, updatedDocKeyIndex.PrefixEnd())}

	n.results.Spans(spans)

	err = n.results.Init()
	if err != nil {
		return false, err
	}

	// get the next result based on our point lookup
	next, err := n.results.Next()
	if err != nil {
		return false, err
	}
	if !next {
		return false, nil
	}

	n.currentValue = n.results.Value()
	return true, nil
}

func (n *updateNode) Kind() string { return "updateNode" }

func (n *updateNode) Spans(spans core.Spans) { /* no-op */ }

func (n *updateNode) Init() error { return nil }

func (n *updateNode) Start() error {
	return n.results.Start()
}

func (n *updateNode) Close() error {
	return n.results.Close()
}

func (n *updateNode) Source() planNode { return n.results }

// Explain method returns a map containing all attributes of this node that
// are to be explained, subscribes / opts-in this node to be an explainablePlanNode.
func (n *updateNode) Explain() (map[string]interface{}, error) {
	explainerMap := map[string]interface{}{}

	// Add the document id(s) that request wants to update.
	explainerMap[idsLabel] = n.ids

	// Add the filter attribute if it exists, otherwise have it nil.
	if n.filter == nil || n.filter.Conditions == nil {
		explainerMap[filterLabel] = nil
	} else {
		explainerMap[filterLabel] = n.filter.Conditions
	}

	// Add the attribute that represents the patch to update with.
	data := map[string]interface{}{}
	err := json.Unmarshal([]byte(n.patch), &data)
	if err != nil {
		return nil, err
	}
	explainerMap[dataLabel] = data

	return explainerMap, nil
}

func (p *Planner) UpdateDocs(parsed *parser.Mutation) (planNode, error) {
	update := &updateNode{
		p:          p,
		filter:     parsed.Filter,
		ids:        parsed.IDs,
		isUpdating: true,
		patch:      parsed.Data,
	}

	// get collection
	col, err := p.db.GetCollectionByName(p.ctx, parsed.Schema)
	if err != nil {
		return nil, err
	}
	update.collection = col.WithTxn(p.txn)

	// create the results Select node
	slct := parsed.ToSelect()
	slctNode, err := p.Select(slct)
	if err != nil {
		return nil, err
	}
	update.results = slctNode
	return update, nil
}
