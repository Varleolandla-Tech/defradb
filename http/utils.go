// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/datastore/badger/v4"
)

func requestJSON(req *http.Request, out any) error {
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func responseJSON(rw http.ResponseWriter, status int, out any) {
	rw.Header().Add("Content-Type", "application/json")
	rw.WriteHeader(status)
	json.NewEncoder(rw).Encode(out) //nolint:errcheck
}

func documentJSON(doc *client.Document) ([]byte, error) {
	docMap, err := doc.ToMap()
	if err != nil {
		return nil, err
	}
	delete(docMap, "_key")

	for field, value := range doc.Values() {
		if !value.IsDirty() {
			delete(docMap, field.Name())
		}
		if value.IsDelete() {
			docMap[field.Name()] = nil
		}
	}

	return json.Marshal(docMap)
}

func parseError(msg any) error {
	switch msg {
	case client.ErrDocumentNotFound.Error():
		return client.ErrDocumentNotFound
	case badger.ErrTxnConflict.Error():
		return badger.ErrTxnConflict
	default:
		return fmt.Errorf("%s", msg)
	}
}
