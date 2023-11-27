// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package gen

import (
	"github.com/sourcenetwork/defradb/client"
)

// GeneratedDoc is a document generated by a document generator.
type GeneratedDoc struct {
	// Col is the collection definition that the document belongs to.
	Col *client.CollectionDefinition
	// Doc is the document generated.
	Doc *client.Document
}
