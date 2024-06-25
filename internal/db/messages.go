// Copyright 2024 Democratized Data Foundation
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
	"context"
	"sync"

	"github.com/sourcenetwork/corelog"

	"github.com/sourcenetwork/defradb/datastore/badger/v4"
	"github.com/sourcenetwork/defradb/errors"
	"github.com/sourcenetwork/defradb/event"
)

func (db *db) handleMessages(ctx context.Context, sub *event.Subscription) {
	queue := newMergeQueue()
	// These are used to ensure we only trigger loadAndPublishP2PCollections and loadAndPublishReplicators
	// once per db instanciation.
	onceReps := sync.Once{}
	onceP2PCollection := sync.Once{}
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-sub.Message():
			if !ok {
				return
			}
			switch evt := msg.Data.(type) {
			case event.Merge:
				go func() {
					// ensure only one merge per docID
					queue.add(evt.DocID)
					defer queue.done(evt.DocID)

					// retry the merge process if a conflict occurs
					//
					// conficts occur when a user updates a document
					// while a merge is in progress.
					var err error
					for i := 0; i < db.MaxTxnRetries(); i++ {
						err = db.executeMerge(ctx, evt)
						if errors.Is(err, badger.ErrTxnConflict) {
							continue // retry merge
						}
						break // merge success or error
					}

					if err != nil {
						log.ErrorContextE(
							ctx,
							"Failed to execute merge",
							err,
							corelog.Any("Event", evt))
					}
				}()
			case event.PeerInfo:
				db.peerInfo.Store(evt.Info)
				// Load and publish P2P collections and replicators once per db instance start.
				// Go routines are used to ensure the message handler is not blocked by these potentially
				// long running operations.
				go onceP2PCollection.Do(func() {
					err := db.loadAndPublishP2PCollections(ctx)
					if err != nil {
						log.ErrorContextE(ctx, "Failed to load P2P collections", err)
					}
				})
				go onceReps.Do(func() {
					err := db.loadAndPublishReplicators(ctx)
					if err != nil {
						log.ErrorContextE(ctx, "Failed to load replicators", err)
					}
				})
			}
		}
	}
}
