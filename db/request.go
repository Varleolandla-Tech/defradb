// Copyright 2022 Democratized Data Foundation
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
	"strings"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/datastore"
	"github.com/sourcenetwork/defradb/planner"
)

// execRequest executes a request against the database.
func (db *db) execRequest(ctx context.Context, request string, txn datastore.Txn) *client.RequestResult {
	res := &client.RequestResult{}
	// check if its Introspection request
	if strings.Contains(request, "IntrospectionQuery") {
		return db.ExecIntrospection(request)
	}

	parsedRequest, errors := db.parser.Parse(request)
	if len(errors) > 0 {
		errorStrings := make([]any, len(errors))
		for i, err := range errors {
			errorStrings[i] = err.Error()
		}
		res.GQL.Errors = errorStrings
		return res
	}

	pub, subRequest, err := db.checkForClientSubsciptions(parsedRequest)
	if err != nil {
		res.GQL.Errors = []any{err.Error()}
		return res
	}

	if pub != nil {
		res.Pub = pub
		go db.handleSubscription(ctx, pub, subRequest)
		return res
	}

	planner := planner.New(ctx, db.WithTxn(txn), txn)

	results, err := planner.RunRequest(ctx, parsedRequest)
	if err != nil {
		res.GQL.Errors = []any{err.Error()}
		return res
	}

	res.GQL.Data = results
	return res
}

// ExecIntrospection executes an introspection request against the database.
func (db *db) ExecIntrospection(request string) *client.RequestResult {
	return db.parser.ExecuteIntrospection(request)
}
