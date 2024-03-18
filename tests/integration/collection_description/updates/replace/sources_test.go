// Copyright 2024 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package replace

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestColDescrUpdateReplaceSources_Errors(t *testing.T) {
	test := testUtils.TestCase{
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {}
				`,
			},
			testUtils.PatchCollection{
				Patch: `
					[
						{ "op": "replace", "path": "/1/Sources", "value": [{"SourceCollectionID": 1}] }
					]
				`,
				ExpectedError: "collection sources cannot be added or removed. CollectionID: 1",
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestColDescrUpdateReplaceSourcesWithQuerySource_Errors(t *testing.T) {
	test := testUtils.TestCase{
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {}
				`,
			},
			testUtils.PatchCollection{
				Patch: `
					[
						{ "op": "replace", "path": "/1/Sources", "value": [{"Query": {"Name": "Users"}}] }
					]
				`,
				ExpectedError: "collection sources cannot be added or removed. CollectionID: 1",
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}
