// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package predefined

// DocsList is a list of document structures that might nest other documents to be replicated
// by a document generator.
//
//	gen.DocsList{
//		ColName: "User",
//		Docs: []map[string]any{
//			{
//				"name":     "Shahzad",
//				"age":      20,
//				"devices": []map[string]any{
//					{
//						"model": "iPhone Xs",
//					},
//				},
//			},
//		},
type DocsList struct {
	// ColName is the name of the collection that the documents in Docs belong to.
	ColName string
	// Docs is a list of documents to be replicated.
	Docs []map[string]any
}
