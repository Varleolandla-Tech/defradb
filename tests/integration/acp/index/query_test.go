// Copyright 2024 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package test_acp_index

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
	acpUtils "github.com/sourcenetwork/defradb/tests/integration/acp"
)

func TestACPWithIndex_UponQueryingPrivateDocWithoutIdentity_ShouldNotFetch(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test acp, querying private doc without identity should not fetch",
		Actions: []any{
			testUtils.AddPolicy{
				Identity:         acpUtils.Actor1Identity,
				Policy:           userPolicy,
				ExpectedPolicyID: "7bcb558ef8dac6b744a11ea144a61a756ea38475554097ac04612037c36ffe52",
			},
			testUtils.SchemaUpdate{
				Schema: `
					type Users @policy(
						id: "7bcb558ef8dac6b744a11ea144a61a756ea38475554097ac04612037c36ffe52",
						resource: "users"
					) {
						name: String @index
						age: Int
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `
					{
						"name": "Shahzad"
					}
				`,
			},
			testUtils.CreateDoc{
				Identity: acpUtils.Actor1Identity,
				Doc: `
					{
						"name": "Islam"
					}
				`,
			},
			testUtils.Request{
				Request: `
					query  {
						Users {
							name
						}
					}`,
				Results: []map[string]any{
					{
						"name": "Shahzad",
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestACPWithIndex_UponQueryingPrivateDocWithIdentity_ShouldFetch(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test acp, querying private doc with identity should  fetch",
		Actions: []any{
			testUtils.AddPolicy{
				Identity:         acpUtils.Actor1Identity,
				Policy:           userPolicy,
				ExpectedPolicyID: "7bcb558ef8dac6b744a11ea144a61a756ea38475554097ac04612037c36ffe52",
			},
			testUtils.SchemaUpdate{
				Schema: `
					type Users @policy(
						id: "7bcb558ef8dac6b744a11ea144a61a756ea38475554097ac04612037c36ffe52",
						resource: "users"
					) {
						name: String @index
						age: Int
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `
					{
						"name": "Shahzad"
					}
				`,
			},
			testUtils.CreateDoc{
				Identity: acpUtils.Actor1Identity,
				Doc: `
					{
						"name": "Islam"
					}
				`,
			},
			testUtils.Request{
				Identity: acpUtils.Actor1Identity,
				Request: `
					query  {
						Users {
							name
						}
					}`,
				Results: []map[string]any{
					{
						"name": "Islam",
					},
					{
						"name": "Shahzad",
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestACPWithIndex_UponQueryingPrivateDocWithWrongIdentity_ShouldNotFetch(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test acp, querying private doc with wrong identity should not fetch",
		Actions: []any{
			testUtils.AddPolicy{
				Identity:         acpUtils.Actor1Identity,
				Policy:           userPolicy,
				ExpectedPolicyID: "7bcb558ef8dac6b744a11ea144a61a756ea38475554097ac04612037c36ffe52",
			},
			testUtils.SchemaUpdate{
				Schema: `
					type Users @policy(
						id: "7bcb558ef8dac6b744a11ea144a61a756ea38475554097ac04612037c36ffe52",
						resource: "users"
					) {
						name: String @index
						age: Int
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `
					{
						"name": "Shahzad"
					}
				`,
			},
			testUtils.CreateDoc{
				Identity: acpUtils.Actor1Identity,
				Doc: `
					{
						"name": "Islam"
					}
				`,
			},
			testUtils.Request{
				Identity: acpUtils.Actor2Identity,
				Request: `
					query  {
						Users {
							name
						}
					}`,
				Results: []map[string]any{
					{
						"name": "Shahzad",
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}
