// Copyright 2020 Source Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.
package db

import (
	"strings"
	"sync"

	"github.com/sourcenetwork/defradb/core"
	_ "github.com/sourcenetwork/defradb/db/fetcher"

	"github.com/fxamacker/cbor/v2"
	ds "github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	"github.com/jbenet/goprocess"
)

// GetterOpts is an options struct used to pass
// preferences, congiurations, and preferences to
// alter the beviour of a `Get(...)` call
//
type GetterOpts struct {
	Fields []string
}

// Think about the possibility of using Option Functions, instead of a public struct.
// This approach creates an interface for exposed options, along with a typed function
// signature used to 'mutate' the options

// DefaultGetterOpts are defualt configuraion settings for a Get
// It will be used, if no others are specified.
var DefaultGetterOpts = GetterOpts{}

func (c *Collection) getAllFields() {}

func (c *Collection) getSomeFields() {}

type fieldResult struct {
	// data [3][]byte // an array of size 3 of byte arrays to hold all the data we need per field pair
	// // The size is 1+number of values.
	// // 1 is from the field name
	// // and the remaining are all the values/metadata need for the field pair
	name  string
	value interface{}
	ctype core.CType
	err   error
}

// may want to abstract into an interface, so different implementations can decode the values as
// they need
type fieldCollector struct {
	queues         map[string]chan query.Entry
	fieldResultsCh chan fieldResult
	process        goprocess.Process
	wg             sync.WaitGroup
	sync.Mutex     // lock for queues map
}

func newFieldCollector() *fieldCollector {
	fc := fieldCollector{
		queues:         make(map[string]chan query.Entry),
		fieldResultsCh: make(chan fieldResult),
		// process:        goprocess.WithParent(goprocess.Background()),
	}
	return &fc
}

func (c *fieldCollector) dispatch(field string, entry query.Entry) {
	c.Lock()
	q, ok := c.queues[field]
	if !ok {
		q = make(chan query.Entry)
		c.queues[field] = q
		// fmt.Println("running new queue process")
		// c.process.Go(func(p goprocess.Process) { // run queue inside its own process so we can control its exit condition
		// 	c.runQueue(p, q)
		// })
		c.wg.Add(1)
		go c.runQueue(q)
	}
	c.Unlock()
	q <- entry
}

// runs the loop for a given queue
// @todo: Handle subobject for fieldCollector
func (c *fieldCollector) runQueue(q chan query.Entry) {
	defer c.wg.Done()
	collected := 0
	res := fieldResult{}
	for entry := range q {
		// fmt.Println("Got a new entry on queue")
		k := ds.NewKey(entry.Key)
		// new entry, parse and insert
		if len(res.name) == 0 {
			res.name = k.Type()
			collected++
		}

		switch k.Name() {
		case "v": // main cbor encoded value
			crdtByte := entry.Value[0]
			res.ctype = core.CType(crdtByte)
			buf := entry.Value[1:]
			err := cbor.Unmarshal(buf, &res.value)
			if err != nil {
				res.err = err
				c.fieldResultsCh <- res
				close(q)
			}
		case "ct": // cached crdt type, which is only a single byte, hence [0]
			res.ctype = core.CType(entry.Value[0])
		}

		// if weve completed all our tasks, close this queue/process down
		collected++
		// fmt.Printf("Collected status: %d/3\n", collected)
		if collected == 2 { // maybe parameterize this constant
			// fmt.Printf("Closing queue and process for %s...\n", res.name)
			c.fieldResultsCh <- res
			close(q)
			// fmt.Println("Closed queue and process for", res.name)
		}
	}
}

func (c *fieldCollector) results() <-chan fieldResult {
	return c.fieldResultsCh
}

type filterPriorityEntry struct{}

func (f filterPriorityEntry) Filter(e query.Entry) bool {
	return !strings.HasSuffix(e.Key, ":p")
}
