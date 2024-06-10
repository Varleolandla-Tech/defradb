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
	test := testUtils.RequestTestCase{
		Description: "Embedded latest commits query within object query",
		Request: `query {
					Users {
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
				`{
					"Name": "John",
					"Age": 21
				}`,
			},
		},
		Results: []map[string]any{
			{
				"Name": "John",
				"Age":  int64(21),
				"_version": []map[string]any{
					{
						"cid": "bafyreiamhlxewin3mgbr6dh3mrbwzvjfngfbwif2qdpjvaldzciivojaiu",
						"links": []map[string]any{
							{
								"cid":  "bafyreibmearhvd62tofeoxhhodzwkz446ehjybll22fyb4tgmnvx2kwfma",
								"name": "Age",
							},
							{
								"cid":  "bafyreid45hs4k3kxxl5t6glfn5ohd6pebjbdhyvtrjmino6g3l2dqdzwiq",
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

func TestQuerySimpleWithEmbeddedLatestCommitWithSchemaVersionID(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Embedded commits query within object query with schema version id",
		Request: `query {
					Users {
						Name
						_version {
							schemaVersionId
						}
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
				"Name": "John",
				"_version": []map[string]any{
					{
						"schemaVersionId": "bafkreigqmcqzkbg3elpe24vfza4rjle2r6cxu7ihzvg56aov57crhaebry",
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithEmbeddedLatestCommitWithDocID(t *testing.T) {
	const docID = "bae-d4303725-7db9-53d2-b324-f3ee44020e52"

	test := testUtils.RequestTestCase{
		Description: "Embedded commits query within object query with document ID",
		Request: `query {
					Users {
						Name
						_docID
						_version {
							docID
						}
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
				"Name":   "John",
				"_docID": docID,
				"_version": []map[string]any{
					{
						"docID": docID,
					},
				},
			},
		},
	}

	executeTestCase(t, test)
}

func TestQuerySimpleWithMultipleAliasedEmbeddedLatestCommit(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Embedded, aliased, latest commits query within object query",
		Request: `query {
					Users {
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
				`{
					"Name": "John",
					"Age": 21
				}`,
			},
		},
		Results: []map[string]any{
			{
				"Name": "John",
				"Age":  int64(21),
				"_version": []map[string]any{
					{
						"cid": "bafyreiamhlxewin3mgbr6dh3mrbwzvjfngfbwif2qdpjvaldzciivojaiu",
						"L1": []map[string]any{
							{
								"cid":  "bafyreibmearhvd62tofeoxhhodzwkz446ehjybll22fyb4tgmnvx2kwfma",
								"name": "Age",
							},
							{
								"cid":  "bafyreid45hs4k3kxxl5t6glfn5ohd6pebjbdhyvtrjmino6g3l2dqdzwiq",
								"name": "Name",
							},
						},
						"L2": []map[string]any{
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

func TestQuery_WithAllCommitFields_NoError(t *testing.T) {
	const docID = "bae-d4303725-7db9-53d2-b324-f3ee44020e52"

	test := testUtils.TestCase{
		Description: "Embedded commits query within object query with document ID",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: userCollectionGQLSchema,
			},
			testUtils.CreateDoc{
				CollectionID: 0,
				Doc: `{
					"Name": "John",
					"Age": 21
				}`,
			},
			testUtils.Request{
				Request: `query {
					Users {
						Name
						_docID
						_version {
							cid
							collectionID
							delta
							docID
							fieldId
							fieldName
							height
							links {
								cid
								name
							}
							schemaVersionId
						}
					}
				}`,
				Results: []map[string]any{
					{
						"Name":   "John",
						"_docID": docID,
						"_version": []map[string]any{
							{
								"cid":          "bafyreiamhlxewin3mgbr6dh3mrbwzvjfngfbwif2qdpjvaldzciivojaiu",
								"collectionID": int64(1),
								"delta":        nil,
								"docID":        "bae-d4303725-7db9-53d2-b324-f3ee44020e52",
								"fieldId":      "C",
								"fieldName":    nil,
								"height":       int64(1),
								"links": []map[string]any{
									{
										"cid":  "bafyreibmearhvd62tofeoxhhodzwkz446ehjybll22fyb4tgmnvx2kwfma",
										"name": "Age",
									},
									{
										"cid":  "bafyreid45hs4k3kxxl5t6glfn5ohd6pebjbdhyvtrjmino6g3l2dqdzwiq",
										"name": "Name",
									},
								},
								"schemaVersionId": "bafkreigqmcqzkbg3elpe24vfza4rjle2r6cxu7ihzvg56aov57crhaebry",
							},
						},
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestQuery_WithAllCommitFieldsWithUpdate_NoError(t *testing.T) {
	const docID = "bae-d4303725-7db9-53d2-b324-f3ee44020e52"

	test := testUtils.TestCase{
		Description: "Embedded commits query within object query with document ID",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: userCollectionGQLSchema,
			},
			testUtils.CreateDoc{
				CollectionID: 0,
				Doc: `{
					"Name": "John",
					"Age": 21
				}`,
			},
			testUtils.UpdateDoc{
				CollectionID: 0,
				DocID:        0,
				Doc:          `{"Age": 22}`,
			},
			testUtils.Request{
				Request: `query {
					Users {
						Name
						Age
						_docID
						_version {
							cid
							collectionID
							delta
							docID
							fieldId
							fieldName
							height
							links {
								cid
								name
							}
							schemaVersionId
						}
					}
				}`,
				Results: []map[string]any{
					{
						"Name":   "John",
						"Age":    int64(22),
						"_docID": docID,
						"_version": []map[string]any{
							{
								"cid":          "bafyreiewiyarxxkzmgss6g35i4h2uiyzoe6kbnmtwaxv4cab6xefnjlzka",
								"collectionID": int64(1),
								"delta":        nil,
								"docID":        docID,
								"fieldId":      "C",
								"fieldName":    nil,
								"height":       int64(2),
								"links": []map[string]any{
									{
										"cid":  "bafyreiamhlxewin3mgbr6dh3mrbwzvjfngfbwif2qdpjvaldzciivojaiu",
										"name": "_head",
									},
									{
										"cid":  "bafyreiejccdc662jvyhia2ee57dvuuzsrsrhbx3hoenojtasofxtix3k7y",
										"name": "Age",
									},
								},
								"schemaVersionId": "bafkreigqmcqzkbg3elpe24vfza4rjle2r6cxu7ihzvg56aov57crhaebry",
							},
							{
								"cid":          "bafyreiamhlxewin3mgbr6dh3mrbwzvjfngfbwif2qdpjvaldzciivojaiu",
								"collectionID": int64(1),
								"delta":        nil,
								"docID":        docID,
								"fieldId":      "C",
								"fieldName":    nil,
								"height":       int64(1),
								"links": []map[string]any{
									{
										"cid":  "bafyreibmearhvd62tofeoxhhodzwkz446ehjybll22fyb4tgmnvx2kwfma",
										"name": "Age",
									},
									{
										"cid":  "bafyreid45hs4k3kxxl5t6glfn5ohd6pebjbdhyvtrjmino6g3l2dqdzwiq",
										"name": "Name",
									},
								},
								"schemaVersionId": "bafkreigqmcqzkbg3elpe24vfza4rjle2r6cxu7ihzvg56aov57crhaebry",
							},
						},
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}
