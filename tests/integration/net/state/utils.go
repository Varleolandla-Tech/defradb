// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package state

import (
	"context"
	"fmt"
	"strings"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/config"
	coreDB "github.com/sourcenetwork/defradb/db"
	"github.com/sourcenetwork/defradb/errors"
	"github.com/sourcenetwork/defradb/logging"
	netutils "github.com/sourcenetwork/defradb/net/utils"
	"github.com/sourcenetwork/defradb/node"
	testutils "github.com/sourcenetwork/defradb/tests/integration"
)

var (
	log = logging.MustNewLogger("defra.test.net")
)

const (
	userCollectionGQLSchema = `
		type Users {
			Name: String
			Email: String
			Age: Int 
			Height: Float
			Verified: Boolean
		}
	`

	userCollection = "Users"
)

type P2PTestCase struct {
	Query string
	// Configuration parameters for each peer
	NodeConfig []*config.Config

	// List of peers for each node.
	// Only peers with lower index than the node can be used in the list of peers.
	NodePeers map[int][]int

	// List of replicator target nodeIds grouped by source peerId.
	// Only peers with lower index than the node can be used in the list of peers.
	NodeReplicators map[int][]int

	SeedDocuments map[int]string

	// node/dockey/value
	Creates map[int]map[int]string
	// node/dockey/values
	Updates map[int]map[int][]string
	// node/dockey/values
	Results map[int]map[int]map[string]any
}

// AnyOf may be used as `P2PTestCase`.`Results` field where the value may
// be one of several values, yet the value of that field must be the same
// across all nodes due to strong eventual consistancy.
type AnyOf []any

func setupDefraNode(t *testing.T, cfg *config.Config, seeds map[int]string) (*node.Node, map[int]client.DocKey, error) {
	ctx := context.Background()
	var err error

	log.Info(ctx, "Building new memory store")
	dbi, err := testutils.NewBadgerMemoryDB(ctx, coreDB.WithUpdateEvents())
	if err != nil {
		return nil, nil, err
	}

	db := dbi.DB()

	if err := seedSchema(ctx, db); err != nil {
		return nil, nil, err
	}

	// seed the database with a set of documents
	docKeysById := map[int]client.DocKey{}
	for id, document := range seeds {
		dockey, err := createDocument(ctx, db, document)
		require.NoError(t, err)
		docKeysById[id] = dockey
	}

	// init the p2p node
	var n *node.Node
	log.Info(ctx, "Starting P2P node", logging.NewKV("P2P address", cfg.Net.P2PAddress))
	n, err = node.NewNode(
		ctx,
		db,
		cfg.NodeConfig(),
	)
	if err != nil {
		return nil, nil, errors.Wrap("failed to start P2P node", err)
	}

	// parse peers and bootstrap
	if len(cfg.Net.Peers) != 0 {
		log.Info(ctx, "Parsing bootstrap peers", logging.NewKV("Peers", cfg.Net.Peers))
		addrs, err := netutils.ParsePeers(strings.Split(cfg.Net.Peers, ","))
		if err != nil {
			return nil, nil, errors.Wrap(fmt.Sprintf("failed to parse bootstrap peers %v", cfg.Net.Peers), err)
		}
		log.Info(ctx, "Bootstrapping with peers", logging.NewKV("Addresses", addrs))
		n.Boostrap(addrs)
	}

	if err := n.Start(); err != nil {
		closeErr := n.Close()
		if closeErr != nil {
			return nil, nil, errors.Wrap(fmt.Sprintf("unable to start P2P listeners: %v: problem closing node", err), closeErr)
		}
		return nil, nil, errors.Wrap("unable to start P2P listeners", err)
	}

	cfg.Net.P2PAddress = n.ListenAddrs()[0].String()

	return n, docKeysById, nil
}

func seedSchema(ctx context.Context, db client.DB) error {
	return db.AddSchema(ctx, userCollectionGQLSchema)
}

func createDocument(ctx context.Context, db client.DB, document string) (client.DocKey, error) {
	col, err := db.GetCollectionByName(ctx, userCollection)
	if err != nil {
		return client.DocKey{}, err
	}

	doc, err := client.NewDocFromJSON([]byte(document))
	if err != nil {
		return client.DocKey{}, err
	}

	err = col.Save(ctx, doc)
	if err != nil {
		return client.DocKey{}, err
	}

	return doc.Key(), nil
}

func updateDocument(ctx context.Context, db client.DB, dockey client.DocKey, update string) error {
	col, err := db.GetCollectionByName(ctx, userCollection)
	if err != nil {
		return err
	}

	doc, err := getDocument(ctx, db, dockey)
	if err != nil {
		return err
	}

	if err := doc.SetWithJSON([]byte(update)); err != nil {
		return err
	}

	return col.Save(ctx, doc)
}

func getDocument(ctx context.Context, db client.DB, dockey client.DocKey) (*client.Document, error) {
	col, err := db.GetCollectionByName(ctx, userCollection)
	if err != nil {
		return nil, err
	}

	doc, err := col.Get(ctx, dockey)
	if err != nil {
		return nil, err
	}
	return doc, err
}

func getAllDocuments(ctx context.Context, db client.DB) (map[string]*client.Document, error) {
	col, err := db.GetCollectionByName(ctx, userCollection)
	if err != nil {
		return nil, err
	}

	docKeys, err := col.GetAllDocKeys(ctx)
	if err != nil {
		return nil, err
	}

	docs := map[string]*client.Document{}
	for docKeyResult := range docKeys {
		if docKeyResult.Err != nil {
			return nil, docKeyResult.Err
		}

		doc, err := col.Get(ctx, docKeyResult.Key)
		if err != nil {
			return nil, err
		}
		docs[docKeyResult.Key.String()] = doc
	}

	return docs, nil
}

func ExecuteTestCase(t *testing.T, test P2PTestCase) {
	ctx := context.Background()

	docKeysById := map[int]client.DocKey{}
	nodes := []*node.Node{}

	for i, cfg := range test.NodeConfig {
		log.Info(ctx, fmt.Sprintf("Setting up node %d", i))
		cfg.Datastore.Badger.Path = t.TempDir()
		if peers, ok := test.NodePeers[i]; ok {
			peerAddresses := []string{}
			for _, p := range peers {
				if p >= len(nodes) {
					log.Info(ctx, "cannot set a peer that hasn't been started. Skipping to next peer")
					continue
				}
				peerAddresses = append(
					peerAddresses,
					fmt.Sprintf("%s/p2p/%s", test.NodeConfig[p].Net.P2PAddress, nodes[p].PeerID()),
				)
			}
			cfg.Net.Peers = strings.Join(peerAddresses, ",")
		}
		n, d, err := setupDefraNode(t, cfg, test.SeedDocuments)
		require.NoError(t, err)

		if i == 0 {
			docKeysById = d
		}
		nodes = append(nodes, n)
	}

	nodeIndexes := map[int]struct{}{}
	for s, n := range test.NodeReplicators {
		nodeIndexes[s] = struct{}{}
		for _, nodeId := range n {
			nodeIndexes[nodeId] = struct{}{}
		}
	}
	for s, n := range test.NodePeers {
		nodeIndexes[s] = struct{}{}
		for _, nodeId := range n {
			nodeIndexes[nodeId] = struct{}{}
		}
	}

	// wait for peers to connect to each other
	if len(test.NodePeers) > 0 {
		for peer1, peers := range test.NodePeers {
			peerIndexes := append([]int{peer1}, peers...)

			for _, i := range peerIndexes {
				n := nodes[i]
				for _, j := range peerIndexes {
					if i == j {
						continue
					}
					p := nodes[j]

					log.Info(ctx, fmt.Sprintf("Waiting for node %d to connect with peer %d", i, j))
					err := n.WaitForPubSubEvent(p.PeerID())
					require.NoError(t, err)
					log.Info(ctx, fmt.Sprintf("Node %d connected to peer %d", i, j))
				}
			}
		}
	}

	if len(test.NodeReplicators) > 0 {
		for i, reps := range test.NodeReplicators {
			n := nodes[i]
			for _, r := range reps {
				addr, err := ma.NewMultiaddr(
					fmt.Sprintf("%s/p2p/%s", test.NodeConfig[r].Net.P2PAddress, nodes[r].PeerID()),
				)
				require.NoError(t, err)
				_, err = n.Peer.SetReplicator(ctx, addr)
				require.NoError(t, err)
			}
		}
	}

	for sourceIndex, docsToCreate := range test.Creates {
		for id, doc := range docsToCreate {
			docKey, err := createDocument(ctx, nodes[sourceIndex].DB, doc)
			require.NoError(t, err)

			docKeysById[id] = docKey

			nodeIndexesToSync := getNodeIndexesToSync(test, sourceIndex, true)
			waitForNodesToSync(ctx, t, nodes, nodeIndexesToSync, sourceIndex)
		}
	}

	for sourceIndex, updateMap := range test.Updates {
		for d, updates := range updateMap {
			for _, update := range updates {
				log.Info(ctx, fmt.Sprintf("Updating node %d with update %d", sourceIndex, d))
				err := updateDocument(ctx, nodes[sourceIndex].DB, docKeysById[d], update)
				require.NoError(t, err)

				nodeIndexesToSync := getNodeIndexesToSync(test, sourceIndex, false)
				waitForNodesToSync(ctx, t, nodes, nodeIndexesToSync, sourceIndex)
			}
		}
	}

	docsByNodeId := map[int]map[string]*client.Document{}
	for nodeIndex, node := range nodes {
		docs, err := getAllDocuments(ctx, node.DB)
		require.NoError(t, err)

		docsByNodeId[nodeIndex] = docs
	}

	require.Equal(t, len(test.Results), len(docsByNodeId))

	anyOfByField := map[docFieldKey][]any{}
	for nodeId, expectedResults := range test.Results {
		docs := docsByNodeId[nodeId]
		require.Equal(t, len(expectedResults), len(docs))

		for docIndex, results := range expectedResults {
			expectedDockey := docKeysById[docIndex]
			require.NotNil(t, expectedDockey)

			doc := docs[expectedDockey.String()]
			require.NotNil(t, doc)

			for field, result := range results {
				val, err := doc.Get(field)
				require.NoError(t, err)

				switch r := result.(type) {
				case AnyOf:
					assert.Contains(t, r, val)

					dfk := docFieldKey{docIndex, field}
					valueSet := anyOfByField[dfk]
					valueSet = append(valueSet, val)
					anyOfByField[dfk] = valueSet
				default:
					assert.Equal(t, result, val)
				}
			}
		}
	}

	// Whilst at a field level the field value of a given document may match any item
	// in the slice, the field value must be consistent across all nodes.  Here we
	// assert this consistency.
	for _, valueSet := range anyOfByField {
		if len(valueSet) < 2 {
			continue
		}
		firstValue := valueSet[0]
		for _, value := range valueSet {
			assert.Equal(t, firstValue, value)
		}
	}

	// clean up
	for _, n := range nodes {
		n.DB.Close(ctx)
		if err := n.Close(); err != nil {
			log.Info(ctx, "node not closing as expected", logging.NewKV("Error", err.Error()))
		}
	}
}

func getNodeIndexesToSync(test P2PTestCase, sourceIndex int, isCreate bool) map[int]struct{} {
	nodeIndexesToSync := map[int]struct{}{}

	// We need to sync all the replicators for this source
	for _, nodeIndex := range test.NodeReplicators[sourceIndex] {
		if nodeIndex != sourceIndex {
			nodeIndexesToSync[nodeIndex] = struct{}{}
		}
	}

	// We should not wait for peers on create, as they do not sync new docs
	if !isCreate {
		// We need to sync all NodePeer indexes that are not the source index
		// (NodePeers map is bi-directional)
		for s, dsts := range test.NodePeers {
			containsSourceIndex := s == sourceIndex
			for _, nodeIndex := range dsts {
				if nodeIndex == sourceIndex {
					containsSourceIndex = true
					break
				}
			}
			if !containsSourceIndex {
				// If the current grouping doesn't contain the source index it is irrelevant
				// here and should be skipped.
				break
			}

			if s != sourceIndex {
				nodeIndexesToSync[s] = struct{}{}
			}
			for _, nodeIndex := range dsts {
				if nodeIndex != sourceIndex {
					nodeIndexesToSync[nodeIndex] = struct{}{}
				}
			}
		}
	}

	return nodeIndexesToSync
}

func waitForNodesToSync(
	ctx context.Context,
	t *testing.T,
	nodes []*node.Node,
	nodeIds map[int]struct{},
	sourceIndex int,
) {
	for nodeId := range nodeIds {
		log.Info(ctx, fmt.Sprintf("Waiting for node %d to sync with peer %d", nodeId, sourceIndex))
		err := nodes[nodeId].WaitForPushLogEvent(nodes[sourceIndex].PeerID())
		require.NoError(t, err)
		log.Info(ctx, fmt.Sprintf("Node %d synced", nodeId))
	}
}

// docFieldKey is an internal key type that wraps docIndex and fieldName
type docFieldKey struct {
	docIndex  int
	fieldName string
}

const randomMultiaddr = "/ip4/0.0.0.0/tcp/0"

func RandomNetworkingConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.Net.P2PAddress = randomMultiaddr
	cfg.Net.RPCAddress = "0.0.0.0:0"
	cfg.Net.TCPAddress = randomMultiaddr
	return cfg
}
