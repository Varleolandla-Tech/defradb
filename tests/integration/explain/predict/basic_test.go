// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package test_explain_predict

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestBasicPredictExplainRequest(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Explain (predict) a basic request.",

		Query: `query @explain(type: predict) {
			author {
				_key
				name
				age
			}
		}`,

		Docs: map[int][]string{
			2: {
				`{
					"name": "John",
					"age": 21
				}`,
			},
		},

		ExpectedError: "predict explain is not yet implemented",
	}

	executeTestCase(t, test)
}
