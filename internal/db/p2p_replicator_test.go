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
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	b58 "github.com/mr-tron/base58/base58"
	"github.com/stretchr/testify/require"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/event"
)

func waitForPeerInfo(db *db, sub *event.Subscription) {
	for msg := range sub.Message() {
		if msg.Name == event.PeerInfoName {
			hasPeerInfo := false
			db.peerMutex.RLock()
			if db.peerInfo.HasValue() {
				hasPeerInfo = true
			}
			db.peerMutex.RUnlock()
			if !hasPeerInfo {
				time.Sleep(1 * time.Millisecond)
			}
			break
		}
	}
}

func TestSetReplicator_WithEmptyPeerInfo_ShouldError(t *testing.T) {
	ctx := context.Background()
	db, err := newDefraMemoryDB(ctx)
	require.NoError(t, err)
	defer db.Close()
	err = db.SetReplicator(ctx, client.Replicator{})
	require.ErrorContains(t, err, "empty peer ID")
}

func TestSetReplicator_WithSelfTarget_ShouldError(t *testing.T) {
	ctx := context.Background()
	db, err := newDefraMemoryDB(ctx)
	require.NoError(t, err)
	defer db.Close()
	sub, err := db.events.Subscribe(event.PeerInfoName)
	require.NoError(t, err)
	db.events.Publish(event.NewMessage(event.PeerInfoName, event.PeerInfo{Info: peer.AddrInfo{ID: "self"}}))
	waitForPeerInfo(db, sub)
	err = db.SetReplicator(ctx, client.Replicator{Info: peer.AddrInfo{ID: "self"}})
	require.ErrorIs(t, err, ErrSelfTargetForReplicator)
}

func TestSetReplicator_WithInvalidCollection_ShouldError(t *testing.T) {
	ctx := context.Background()
	db, err := newDefraMemoryDB(ctx)
	require.NoError(t, err)
	defer db.Close()
	sub, err := db.events.Subscribe(event.PeerInfoName)
	require.NoError(t, err)
	db.events.Publish(event.NewMessage(event.PeerInfoName, event.PeerInfo{Info: peer.AddrInfo{ID: "self"}}))
	waitForPeerInfo(db, sub)
	err = db.SetReplicator(ctx, client.Replicator{
		Info:    peer.AddrInfo{ID: "other"},
		Schemas: []string{"invalidCollection"},
	})
	require.ErrorIs(t, err, ErrReplicatorCollections)
}

func TestSetReplicator_WithValidCollection_ShouldSucceed(t *testing.T) {
	ctx := context.Background()
	db, err := newDefraMemoryDB(ctx)
	require.NoError(t, err)
	defer db.Close()
	sub, err := db.events.Subscribe(event.ReplicatorName)
	require.NoError(t, err)
	cols, err := db.AddSchema(ctx, `type User { name: String }`)
	require.NoError(t, err)
	schema, err := db.GetSchemaByVersionID(ctx, cols[0].SchemaVersionID)
	require.NoError(t, err)
	err = db.SetReplicator(ctx, client.Replicator{
		Info:    peer.AddrInfo{ID: "other"},
		Schemas: []string{"User"},
	})
	require.NoError(t, err)
	for msg := range sub.Message() {
		if msg.Name == event.ReplicatorName {
			replicator := msg.Data.(event.Replicator)
			require.Equal(t, peer.ID("other"), replicator.Info.ID)
			require.Equal(t, map[string]struct{}{schema.Root: {}}, replicator.Schemas)
			break
		}
	}
}

func TestSetReplicator_WithValidCollectionWithDoc_ShouldSucceed(t *testing.T) {
	ctx := context.Background()
	db, err := newDefraMemoryDB(ctx)
	require.NoError(t, err)
	defer db.Close()
	sub, err := db.events.Subscribe(event.ReplicatorName)
	require.NoError(t, err)
	cols, err := db.AddSchema(ctx, `type User { name: String }`)
	require.NoError(t, err)
	col, err := db.GetCollectionByName(ctx, cols[0].Name.Value())
	require.NoError(t, err)
	doc, err := client.NewDocFromMap(map[string]any{"name": "Alice"}, col.Definition())
	require.NoError(t, err)
	err = col.Create(ctx, doc)
	require.NoError(t, err)

	err = db.SetReplicator(ctx, client.Replicator{
		Info:    peer.AddrInfo{ID: "other"},
		Schemas: []string{"User"},
	})
	require.NoError(t, err)
	for msg := range sub.Message() {
		if msg.Name == event.ReplicatorName {
			replicator := msg.Data.(event.Replicator)
			require.Equal(t, peer.ID("other"), replicator.Info.ID)
			require.Equal(t, map[string]struct{}{col.SchemaRoot(): {}}, replicator.Schemas)
			for docEvt := range replicator.Docs {
				require.Equal(t, doc.ID().String(), docEvt.DocID)
			}
			break
		}
	}
}

func TestDeleteReplicator_WithEmptyPeerInfo_ShouldError(t *testing.T) {
	ctx := context.Background()
	db, err := newDefraMemoryDB(ctx)
	require.NoError(t, err)
	defer db.Close()
	err = db.DeleteReplicator(ctx, client.Replicator{})
	require.ErrorContains(t, err, "empty peer ID")
}

func TestDeleteReplicator_WithValidCollection_ShouldSucceed(t *testing.T) {
	b, err := b58.Decode("12D3KooWB8Na2fKhdGtej5GjoVhmBBYFvqXiqFCSkR7fJFWHUbNr")
	require.NoError(t, err)
	peerID, err := peer.IDFromBytes(b)
	require.NoError(t, err)
	ctx := context.Background()
	db, err := newDefraMemoryDB(ctx)
	require.NoError(t, err)
	defer db.Close()
	sub, err := db.events.Subscribe(event.ReplicatorName)
	require.NoError(t, err)
	cols, err := db.AddSchema(ctx, `type User { name: String }`)
	require.NoError(t, err)
	schema, err := db.GetSchemaByVersionID(ctx, cols[0].SchemaVersionID)
	require.NoError(t, err)
	err = db.SetReplicator(ctx, client.Replicator{
		Info:    peer.AddrInfo{ID: peerID},
		Schemas: []string{"User"},
	})
	require.NoError(t, err)
	for msg := range sub.Message() {
		if msg.Name == event.ReplicatorName {
			replicator := msg.Data.(event.Replicator)
			require.Equal(t, peer.ID(peerID), replicator.Info.ID)
			require.Equal(t, map[string]struct{}{schema.Root: {}}, replicator.Schemas)
			break
		}
	}

	err = db.DeleteReplicator(ctx, client.Replicator{Info: peer.AddrInfo{ID: peerID}})
	require.NoError(t, err)
	for msg := range sub.Message() {
		if msg.Name == event.ReplicatorName {
			replicator := msg.Data.(event.Replicator)
			require.Equal(t, peer.ID(peerID), replicator.Info.ID)
			require.Equal(t, map[string]struct{}{}, replicator.Schemas)
			break
		}
	}
}

func TestGetAllReplicators_WithValidCollection_ShouldSucceed(t *testing.T) {
	b, err := b58.Decode("12D3KooWB8Na2fKhdGtej5GjoVhmBBYFvqXiqFCSkR7fJFWHUbNr")
	require.NoError(t, err)
	peerID, err := peer.IDFromBytes(b)
	require.NoError(t, err)
	ctx := context.Background()
	db, err := newDefraMemoryDB(ctx)
	require.NoError(t, err)
	defer db.Close()
	sub, err := db.events.Subscribe(event.ReplicatorName)
	require.NoError(t, err)
	cols, err := db.AddSchema(ctx, `type User { name: String }`)
	require.NoError(t, err)
	schema, err := db.GetSchemaByVersionID(ctx, cols[0].SchemaVersionID)
	require.NoError(t, err)
	err = db.SetReplicator(ctx, client.Replicator{
		Info:    peer.AddrInfo{ID: peerID},
		Schemas: []string{"User"},
	})
	require.NoError(t, err)
	for msg := range sub.Message() {
		if msg.Name == event.ReplicatorName {
			replicator := msg.Data.(event.Replicator)
			require.Equal(t, peer.ID(peerID), replicator.Info.ID)
			require.Equal(t, map[string]struct{}{schema.Root: {}}, replicator.Schemas)
			break
		}
	}

	reps, err := db.GetAllReplicators(ctx)
	require.NoError(t, err)
	require.Equal(t, peerID, reps[0].Info.ID)
	require.Equal(t, []string{schema.Root}, reps[0].Schemas)
}
