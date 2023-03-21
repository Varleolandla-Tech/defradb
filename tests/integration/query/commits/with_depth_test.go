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

func TestQueryCommitsWithDepth1(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with depth 1",
		Request: `query {
					commits(depth: 1) {
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
				"cid": "bafybeiaeic6vhiiw5zu6ju7e47cclvctn6t5pb36fj3mczchyhmctbrr6m",
			},
			{
				"cid": "bafybeibsaubd2ptp6qqsszv24p73j474amc4pll4oyssnpilofrl575hmy",
			},
			{
				"cid": "bafybeidcatznm2mlsymcytrh5fkpdrazensg5fsvn2uavcgiq2bf26lzey",
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryCommitsWithDepth1WithUpdate(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with depth 1, and doc updates",
		Request: `query {
					commits(depth: 1) {
						cid
						height
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
		Updates: map[int]map[int][]string{
			0: {
				0: {
					`{
						"Age": 22
					}`,
				},
			},
		},
		Results: []map[string]any{
			{
				"cid":    "bafybeihxc6ittcok3rnetguamxfzd3wa534z7zwqsaoppvawu7jx4rdy5u",
				"height": int64(2),
			},
			{
				// "Name" field head (unchanged from create)
				"cid":    "bafybeibsaubd2ptp6qqsszv24p73j474amc4pll4oyssnpilofrl575hmy",
				"height": int64(1),
			},
			{
				// "Age" field head
				"cid":    "bafybeidxeexqpsbf2qqrrkrysdztf2q5mqfwabwrcxdkjuolf6fsyzzyh4",
				"height": int64(2),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryCommitsWithDepth2WithUpdate(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with depth 2, and doc updates",
		Request: `query {
					commits(depth: 2) {
						cid
						height
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
		Updates: map[int]map[int][]string{
			0: {
				0: {
					`{
						"Age": 22
					}`,
					`{
						"Age": 23
					}`,
				},
			},
		},
		Results: []map[string]any{
			{
				// Composite head
				"cid":    "bafybeifaxl4u5wmokgr4jviru6dz7teg7f2fomusxrvh7o5nh2a32jk3va",
				"height": int64(3),
			},
			{
				// Composite head -1
				"cid":    "bafybeihxc6ittcok3rnetguamxfzd3wa534z7zwqsaoppvawu7jx4rdy5u",
				"height": int64(2),
			},
			{
				// "Name" field head (unchanged from create)
				"cid":    "bafybeibsaubd2ptp6qqsszv24p73j474amc4pll4oyssnpilofrl575hmy",
				"height": int64(1),
			},
			{
				// "Age" field head
				"cid":    "bafybeieh6icybinqmuz7or7nqjt445zu2qbnxccuu64i5jhgonhlj2k5sy",
				"height": int64(3),
			},
			{
				// "Age" field head -1
				"cid":    "bafybeidxeexqpsbf2qqrrkrysdztf2q5mqfwabwrcxdkjuolf6fsyzzyh4",
				"height": int64(2),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryCommitsWithDepth1AndMultipleDocs(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with depth 1",
		Request: `query {
					commits(depth: 1) {
						cid
					}
				}`,
		Docs: map[int][]string{
			0: {
				`{
					"Name": "John",
					"Age": 21
				}`,
				`{
					"Name": "Fred",
					"Age": 25
				}`,
			},
		},
		Results: []map[string]any{
			{
				"cid": "bafybeiaeic6vhiiw5zu6ju7e47cclvctn6t5pb36fj3mczchyhmctbrr6m",
			},
			{
				"cid": "bafybeibsaubd2ptp6qqsszv24p73j474amc4pll4oyssnpilofrl575hmy",
			},
			{
				"cid": "bafybeidcatznm2mlsymcytrh5fkpdrazensg5fsvn2uavcgiq2bf26lzey",
			},
			{
				"cid": "bafybeie4ciqu6dwoovbrzjuzlpy6ene3ahhiqz7ocrcxeb2h4zkifhqdr4",
			},
			{
				"cid": "bafybeifj66t5p5df7ksiod6asvyyk6zduejzd7pncbpnaospn5mmjdr5bq",
			},
			{
				"cid": "bafybeielpy36cijvx3ffpq3oxd4knmui7h5hrruvcb5it4homf5krylpsi",
			},
		},
	}

	executeTestCase(t, test)
}
