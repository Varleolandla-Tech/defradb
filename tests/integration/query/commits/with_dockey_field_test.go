// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package commits

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestQueryCommitsWithDockeyAndUnknownField(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with dockey and unknown field",
		Request: `query {
					commits(dockey: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f", field: "not a field") {
						cid
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 21
				}`,
			},
		},
		Results: []map[string]any{},
	}

	executeTestCase(t, test)
}

func TestQueryCommitsWithDockeyAndUnknownFieldId(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with dockey and unknown field id",
		Request: `query {
					commits(dockey: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f", field: "999999") {
						cid
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 21
				}`,
			},
		},
		Results: []map[string]any{},
	}

	executeTestCase(t, test)
}

// This test is for documentation reasons only. This is not
// desired behaviour (should return all commits for dockey-field).
func TestQueryCommitsWithDockeyAndField(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with dockey and field",
		Request: `query {
					commits(dockey: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f", field: "Age") {
						cid
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 21
				}`,
			},
		},
		Results: []map[string]any{},
	}

	executeTestCase(t, test)
}

// This test is for documentation reasons only. This is not
// desired behaviour (users should not be specifying field ids).
func TestQueryCommitsWithDockeyAndFieldId(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with dockey and field id",
		Request: `query {
					commits(dockey: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f", field: "1") {
						cid
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 21
				}`,
			},
		},
		Results: []map[string]any{
			{
				"cid": "bafybeigju7dgicfq3fxvtlxtjao7won4xc7kusykkvumngjfx5i2c7ibny",
			},
		},
	}

	executeTestCase(t, test)
}

// This test is for documentation reasons only. This is not
// desired behaviour (users should not be specifying field ids).
func TestQueryCommitsWithDockeyAndCompositeFieldId(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with dockey and field id",
		Request: `query {
					commits(dockey: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f", field: "C") {
						cid
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 21
				}`,
			},
		},
		Results: []map[string]any{
			{
				"cid": "bafybeid5l577igkgcn6wjqjeqxlta4dcc3a3iykwkborf4fklaenjuctoq",
			},
		},
	}

	executeTestCase(t, test)
}
