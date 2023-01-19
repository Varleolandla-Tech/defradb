// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package peer_replicator_test

import (
	"testing"

	"github.com/sourcenetwork/defradb/config"
	testUtils "github.com/sourcenetwork/defradb/tests/integration/net/state"
)

func TestP2PPeerReplicatorWithUpdate(t *testing.T) {
	test := testUtils.P2PTestCase{
		NodeConfig: []*config.Config{
			testUtils.RandomNetworkingConfig(),
			testUtils.RandomNetworkingConfig(),
			testUtils.RandomNetworkingConfig(),
		},
		NodePeers: map[int][]int{
			1: {
				0,
			},
		},
		NodeReplicators: map[int][]int{
			0: {
				2,
			},
		},
		SeedDocuments: map[int]string{
			0: `{
				"Name": "John",
				"Age": 21
			}`,
		},
		Updates: map[int]map[int][]string{
			0: {
				0: {
					`{
						"Age": 60
					}`,
				},
			},
		},
		Results: map[int]map[int]map[string]any{
			0: {
				0: {
					"Age": uint64(60),
				},
			},
			1: {
				0: {
					// Updated via peer
					"Age": uint64(60),
				},
			},
			2: {
				0: {
					// Updated via replicator
					"Age": uint64(60),
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}
