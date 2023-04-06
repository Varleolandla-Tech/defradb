// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package client

import (
	"context"

	blockstore "github.com/ipfs/go-ipfs-blockstore"

	"github.com/sourcenetwork/defradb/datastore"
	"github.com/sourcenetwork/defradb/events"
)

// DB is the primary public programatic access point to the local Defra instance.
//
// It should be contructed via the [db] package, via the [db.NewDB] function.
type DB interface {
	// Store contains Defra database functions protected by an internal, short-lived, transaction, allowing safe
	// access to common database read and write operations.
	Store

	// NewTxn returns a new transaction on the root store that may be managed externally.
	//
	// It may be used with other functions in the client package. It is not threadsafe.
	NewTxn(context.Context, bool) (datastore.Txn, error)

	// NewConcurrentTxn returns a new transaction on the root store that may be managed externally.
	//
	// It may be used with other functions in the client package. It is threadsafe and mutliple threads/Go routines
	// can safely operate on it concurrently.
	NewConcurrentTxn(context.Context, bool) (datastore.Txn, error)

	// WithTxn returns a new [client.Store] that respects the given transaction.
	WithTxn(datastore.Txn) Store

	// Root returns the underlying root store, within which all data managed by Defra is held.
	Root() datastore.RootStore

	// Blockstore returns the blockstore, within which all blocks (commits) managed by Defra are held.
	//
	// It sits within the rootstore returned by [Root].
	Blockstore() blockstore.Blockstore

	// Close closes the database instance and releases any resources held.
	//
	// The behaviour of other functions in this package after this function has been called is undefined
	// unless explicitly stated on the function in question.
	//
	// It does not explicitly clear any data from persisted storage, and a new [DB] instance may typically
	// be created after calling this to resume operations on the prior data - this is however dependant on
	// the behaviour of the rootstore provided on database instance creation, as this function will Close
	// the provided rootstore.
	Close(context.Context)

	Events() events.Events

	MaxTxnRetries() int

	PrintDump(ctx context.Context) error
}

type Store interface {
	// P2P holds the P2P related methods that must be implemented by the database.
	P2P

	AddSchema(context.Context, string) error

	// PatchSchema takes the given JSON patch string and applies it to the set of CollectionDescriptions
	// present in the database.
	//
	// It will also update the GQL types used by the query system. It will error and not apply any of the
	// requested, valid updates should the net result of the patch result in an invalid state.  The
	// individual operations defined in the patch do not need to result in a valid state, only the net result
	// of the full patch.
	//
	// The collections (including the schema version ID) will only be updated if any changes have actually
	// been made, if the net result of the patch matches the current persisted description then no changes
	// will be applied.
	//
	// Field [FieldKind] values may be provided in either their raw integer form, or as string as per
	// [FieldKindStringToEnumMapping].
	PatchSchema(context.Context, string) error

	CreateCollection(context.Context, CollectionDescription) (Collection, error)

	// UpdateCollection updates the persisted collection description matching the name of the given
	// description, to the values in the given description.
	//
	// It will validate the given description using [ValidateUpdateCollection] before updating it.
	//
	// The collection (including the schema version ID) will only be updated if any changes have actually
	// been made, if the given description matches the current persisted description then no changes will be
	// applied.
	UpdateCollection(context.Context, CollectionDescription) (Collection, error)

	// ValidateUpdateCollection validates that the given collection description is a valid update.
	//
	// Will return true if the given desctiption differs from the current persisted state of the
	// collection. Will return an error if it fails validation.
	ValidateUpdateCollection(context.Context, CollectionDescription) (bool, error)

	GetCollectionByName(context.Context, string) (Collection, error)
	GetCollectionBySchemaID(context.Context, string) (Collection, error)
	GetCollectionByVersionID(context.Context, string) (Collection, error)
	GetAllCollections(context.Context) ([]Collection, error)

	ExecRequest(context.Context, string) *RequestResult
}

type GQLResult struct {
	Errors []any `json:"errors,omitempty"`
	Data   any   `json:"data"`
}

type RequestResult struct {
	GQL GQLResult
	Pub *events.Publisher[events.Update]
}
