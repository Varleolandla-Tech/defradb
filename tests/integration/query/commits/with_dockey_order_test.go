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

func TestQueryCommitsWithDockeyAndOrderHeightDesc(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with dockey, order height desc",
		Request: `query {
					commits(dockey: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f", order: {height: DESC}) {
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
				"cid":    "bafybeigeigzhjtf27o3wkdyq3exmnqhr3npt5psdq3pywpwxxdepiebpdi",
				"height": int64(2),
			},
			{
				"cid":    "bafybeiaeic6vhiiw5zu6ju7e47cclvctn6t5pb36fj3mczchyhmctbrr6m",
				"height": int64(1),
			},
			{
				"cid":    "bafybeibsaubd2ptp6qqsszv24p73j474amc4pll4oyssnpilofrl575hmy",
				"height": int64(1),
			},
			{
				"cid":    "bafybeidr2z5ahvvss5j664gxyna5wjil5ndfjbmllnsewkjf6cnsvsmmqu",
				"height": int64(1),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryCommitsWithDockeyAndOrderHeightAsc(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with dockey, order height asc",
		Request: `query {
					commits(dockey: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f", order: {height: ASC}) {
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
				"cid":    "bafybeiaeic6vhiiw5zu6ju7e47cclvctn6t5pb36fj3mczchyhmctbrr6m",
				"height": int64(1),
			},
			{
				"cid":    "bafybeibsaubd2ptp6qqsszv24p73j474amc4pll4oyssnpilofrl575hmy",
				"height": int64(1),
			},
			{
				"cid":    "bafybeidr2z5ahvvss5j664gxyna5wjil5ndfjbmllnsewkjf6cnsvsmmqu",
				"height": int64(1),
			},
			{
				"cid":    "bafybeihxc6ittcok3rnetguamxfzd3wa534z7zwqsaoppvawu7jx4rdy5u",
				"height": int64(2),
			},
			{
				"cid":    "bafybeigeigzhjtf27o3wkdyq3exmnqhr3npt5psdq3pywpwxxdepiebpdi",
				"height": int64(2),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryCommitsWithDockeyAndOrderCidDesc(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with dockey, order cid desc",
		Request: `query {
					commits(dockey: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f", order: {cid: DESC}) {
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
				"cid":    "bafybeigeigzhjtf27o3wkdyq3exmnqhr3npt5psdq3pywpwxxdepiebpdi",
				"height": int64(2),
			},
			{
				"cid":    "bafybeidr2z5ahvvss5j664gxyna5wjil5ndfjbmllnsewkjf6cnsvsmmqu",
				"height": int64(1),
			},
			{
				"cid":    "bafybeibsaubd2ptp6qqsszv24p73j474amc4pll4oyssnpilofrl575hmy",
				"height": int64(1),
			},
			{
				"cid":    "bafybeiaeic6vhiiw5zu6ju7e47cclvctn6t5pb36fj3mczchyhmctbrr6m",
				"height": int64(1),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryCommitsWithDockeyAndOrderCidAsc(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with dockey, order cid asc",
		Request: `query {
					commits(dockey: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f", order: {cid: ASC}) {
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
				"cid":    "bafybeiaeic6vhiiw5zu6ju7e47cclvctn6t5pb36fj3mczchyhmctbrr6m",
				"height": int64(1),
			},
			{
				"cid":    "bafybeibsaubd2ptp6qqsszv24p73j474amc4pll4oyssnpilofrl575hmy",
				"height": int64(1),
			},
			{
				"cid":    "bafybeidr2z5ahvvss5j664gxyna5wjil5ndfjbmllnsewkjf6cnsvsmmqu",
				"height": int64(1),
			},
			{
				"cid":    "bafybeigeigzhjtf27o3wkdyq3exmnqhr3npt5psdq3pywpwxxdepiebpdi",
				"height": int64(2),
			},
			{
				"cid":    "bafybeihxc6ittcok3rnetguamxfzd3wa534z7zwqsaoppvawu7jx4rdy5u",
				"height": int64(2),
			},
		},
	}

	executeTestCase(t, test)
}

func TestQueryCommitsWithDockeyAndOrderAndMultiUpdatesCidAsc(t *testing.T) {
	test := testUtils.RequestTestCase{
		Description: "Simple all commits query with dockey, multiple updates with order cid asc",
		Request: `query {
                     commits(dockey: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f", order: {height: ASC}) {
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
					`{
                         "Age": 24
                     }`,
				},
			},
		},
		Results: []map[string]any{
			{
				"cid":    "bafybeiaeic6vhiiw5zu6ju7e47cclvctn6t5pb36fj3mczchyhmctbrr6m",
				"height": int64(1),
			},
			{
				"cid":    "bafybeibsaubd2ptp6qqsszv24p73j474amc4pll4oyssnpilofrl575hmy",
				"height": int64(1),
			},
			{
				"cid":    "bafybeidr2z5ahvvss5j664gxyna5wjil5ndfjbmllnsewkjf6cnsvsmmqu",
				"height": int64(1),
			},
			{
				"cid":    "bafybeihxc6ittcok3rnetguamxfzd3wa534z7zwqsaoppvawu7jx4rdy5u",
				"height": int64(2),
			},
			{
				"cid":    "bafybeigeigzhjtf27o3wkdyq3exmnqhr3npt5psdq3pywpwxxdepiebpdi",
				"height": int64(2),
			},
			{
				"cid":    "bafybeifaxl4u5wmokgr4jviru6dz7teg7f2fomusxrvh7o5nh2a32jk3va",
				"height": int64(3),
			},
			{
				"cid":    "bafybeifodfb4kakigrsaobafpz2xogmylr33qphdjjkumseu7dkzlpbvem",
				"height": int64(3),
			},
			{
				"cid":    "bafybeic4slf53yiert4jrdeyvqij3rnat2iikgbn7fdn6n6zowu66dylbi",
				"height": int64(4),
			},
			{
				"cid":    "bafybeid6gm7723nfhmxqprclrnynxyyaf5mddxq2ggjqy4h344tykzpig4",
				"height": int64(4),
			},
		},
	}

	executeTestCase(t, test)
}
