// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package simple

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestQuerySimpleWithEmbeddedLatestCommit(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Embedded latest commits query within object query",
		Query: `query {
					users {
						Name
						Age
						_version {
							cid
							links {
								cid
								name
							}
						}
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "John",
				"Age": 21
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"Name": "John",
				"Age":  uint64(21),
				"_version": []map[string]interface{}{
					{
						"cid": "bafybeihtn2xjbjjqxeqp2uhwhvk3tmjfkaf2qtfqh5w5q3ews7ax2dc75a",
						"links": []map[string]interface{}{
							{
								"cid":  "bafybeidst2mzxhdoh4ayjdjoh4vibo7vwnuoxk3xgyk5mzmep55jklni2a",
								"name": "Age",
							},
							{
								"cid":  "bafybeidkse2jiqekdebh6zdq4zvyx4gzyrupujbtb6gd7qqdb4hj3pyaeq",
								"name": "Name",
							},
						},
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithMultipleAliasedEmbeddedLatestCommit(t *testing.T) {
	test := testUtils.QueryTestCase{
		Description: "Embedded, aliased, latest commits query within object query",
		Query: `query {
					users {
						Name
						Age
						_version {
							cid
							L1: links {
								cid
								name
							}
							L2: links {
								name
							}
						}
					}
				}`,
		Docs: map[int][]string{
			0: {
				(`{
				"Name": "John",
				"Age": 21
			}`)},
		},
		Results: []map[string]interface{}{
			{
				"Name": "John",
				"Age":  uint64(21),
				"_version": []map[string]interface{}{
					{
						"cid": "bafybeihtn2xjbjjqxeqp2uhwhvk3tmjfkaf2qtfqh5w5q3ews7ax2dc75a",
						"L1": []map[string]interface{}{
							{
								"cid":  "bafybeidst2mzxhdoh4ayjdjoh4vibo7vwnuoxk3xgyk5mzmep55jklni2a",
								"name": "Age",
							},
							{
								"cid":  "bafybeidkse2jiqekdebh6zdq4zvyx4gzyrupujbtb6gd7qqdb4hj3pyaeq",
								"name": "Name",
							},
						},
						"L2": []map[string]interface{}{
							{
								"name": "Age",
							},
							{
								"name": "Name",
							},
						},
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}
