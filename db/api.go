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
	"fmt"

	api "github.com/sourcenetwork/defradb/api/http"
)

func (db *DB) Listen(ctx context.Context, address string) error {
	log.Info(ctx, fmt.Sprintf("Running HTTP API at http://%s. Try it out at > curl http://%s/graphql", address, address))

	s := api.NewServer(db)
	return s.Listen(address)
}

// func (db *DB) handlePing(w http.ResponseWriter, r *http.Request) {
// 	w.Write([]byte("pong"))
// }

// func (db *DB) handleGraphqlReq(w http.ResponseWriter, r *http.Request) {
// 	query := r.URL.Query().Get("query")
// 	result := db.ExecQuery(query)
// 	json.NewEncoder(w).Encode(result)
// }
