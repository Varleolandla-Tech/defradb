// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package net

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	coreClient "github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/config"
	coreDB "github.com/sourcenetwork/defradb/db"
	"github.com/sourcenetwork/defradb/logging"
	netutils "github.com/sourcenetwork/defradb/net/utils"
	"github.com/sourcenetwork/defradb/node"
	testutils "github.com/sourcenetwork/defradb/tests/integration"
	"github.com/stretchr/testify/assert"
	"github.com/textileio/go-threads/broadcast"
)

var (
	busBufferSize = 100
	log           = logging.MustNewLogger("defra.test.net")
)

const userCollectionGQLSchema = `
	type users {
		Name: String
		Email: String
		Age: Int 
		HeightM: Float
		Verified: Boolean
	}
`

const userCollection = "users"

type P2PTestCase struct {
	Description string

	// Configuration parameters for each peer
	NodeConfig []*config.Config

	// List of peers for each node.
	// Only peers with lower index than the node can be used in the list of peers.
	NodePeers map[int][]int

	Seeds []string

	// node/dockey/values
	Updates map[int]map[int][]string
	Results map[int]map[int]map[string]interface{}
}

func setupDefraNode(t *testing.T, cfg *config.Config, seeds []string) (*node.Node, []coreClient.DocKey, error) {
	ctx := context.Background()
	var err error

	log.Info(ctx, "Building new memory store")
	bs := broadcast.NewBroadcaster(busBufferSize)
	dbi, err := testutils.NewBadgerMemoryDB(ctx, coreDB.WithBroadcaster(bs))
	if err != nil {
		return nil, nil, err
	}

	db := dbi.DB()

	if err := seedSchema(ctx, db); err != nil {
		return nil, nil, err
	}

	// seed the database with a set of documents
	dockeys := []coreClient.DocKey{}
	for _, document := range seeds {
		dockey, err := seedDocument(ctx, db, document)
		if err != nil {
			t.Fatal(err)
		}
		dockeys = append(dockeys, dockey)
	}

	// init the p2p node
	var n *node.Node
	log.Info(ctx, "Starting P2P node", logging.NewKV("P2P address", cfg.Net.P2PAddress))
	n, err = node.NewNode(
		ctx,
		db,
		bs,
		cfg.NodeConfig(),
	)
	if err != nil {
		n.Close() //nolint:errcheck
		db.Close(ctx)
		return nil, nil, fmt.Errorf("failed to start P2P node: %w", err)
	}

	// parse peers and bootstrap
	if len(cfg.Net.Peers) != 0 {
		log.Info(ctx, "Parsing bootstrap peers", logging.NewKV("Peers", cfg.Net.Peers))
		addrs, err := netutils.ParsePeers(strings.Split(cfg.Net.Peers, ","))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse bootstrap peers %v: %w", cfg.Net.Peers, err)
		}
		log.Info(ctx, "Bootstrapping with peers", logging.NewKV("Addresses", addrs))
		n.Boostrap(addrs)
	}

	if err := n.Start(); err != nil {
		n.Close() //nolint:errcheck
		db.Close(ctx)
		return nil, nil, fmt.Errorf("unable to start P2P listeners: %w", err)
	}

	return n, dockeys, nil
}

func seedSchema(ctx context.Context, db coreClient.DB) error {
	return db.AddSchema(ctx, userCollectionGQLSchema)
}

func seedDocument(ctx context.Context, db coreClient.DB, document string) (coreClient.DocKey, error) {
	col, err := db.GetCollectionByName(ctx, userCollection)
	if err != nil {
		return coreClient.DocKey{}, err
	}

	doc, err := coreClient.NewDocFromJSON([]byte(document))
	if err != nil {
		return coreClient.DocKey{}, err
	}

	err = col.Save(ctx, doc)
	if err != nil {
		return coreClient.DocKey{}, err
	}

	return doc.Key(), nil
}

func updateDocument(ctx context.Context, db coreClient.DB, dockey coreClient.DocKey, update string) error {
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

func getDocument(ctx context.Context, db coreClient.DB, dockey coreClient.DocKey) (*coreClient.Document, error) {
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

func executeTestCase(t *testing.T, test P2PTestCase) {
	ctx := context.Background()

	dockeys := []coreClient.DocKey{}
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
		n, d, err := setupDefraNode(t, cfg, test.Seeds)
		if err != nil {
			t.Fatal(err)
		}

		if i == 0 {
			dockeys = append(dockeys, d...)
		}
		nodes = append(nodes, n)
	}

	// wait for peers to connect to each other
	for i, n := range nodes {
		for j, p := range nodes {
			if i == j {
				continue
			}
			log.Info(ctx, fmt.Sprintf("Waiting for node %d to connect with peer %d", i, j))
			err := n.WaitForPeerConnectionEvent(p.PeerID())
			if err != nil {
				t.Fatal(err)
			}
			log.Info(ctx, fmt.Sprintf("Node %d connected to peer %d", i, j))
		}
	}

	// update and sync peers
	for n, updateMap := range test.Updates {
		if n > len(nodes) {
			log.Info(ctx, "cannot update a node that hasn't been started. Skipping to next node")
			continue
		}

		for d, updates := range updateMap {
			for _, update := range updates {
				log.Info(ctx, fmt.Sprintf("Updating node %d with update %d", n, d))
				if err := updateDocument(ctx, nodes[n].DB, dockeys[d], update); err != nil {
					t.Fatal(err)
				}

				// wait for peers to sync
				for n2, p := range nodes {
					if n2 == n {
						continue
					}
					log.Info(ctx, fmt.Sprintf("Waiting for node %d to sync with peer %d", n2, n))
					p.WaitForPushLogEvent(nodes[n].PeerID())
					log.Info(ctx, fmt.Sprintf("Node %d synced", n2))
				}
			}
		}

		// check that peers actually received the update
		for n2, resultsMap := range test.Results {
			if n2 == n {
				continue
			}
			if n2 > len(nodes) {
				log.Info(ctx, "cannot check results of a node that hasn't been started. Skipping to next node")
				continue
			}

			for d, results := range resultsMap {
				for field, result := range results {
					doc, err := getDocument(ctx, nodes[n2].DB, dockeys[d])
					if err != nil {
						t.Fatal(err)
					}

					val, err := doc.Get(field)
					if err != nil {
						t.Fatal(err)
					}

					assert.Equal(t, result, val)
				}
			}
		}
	}

	// clean up
	for _, n := range nodes {
		n.DB.Close(ctx)
		if err := n.Close(); err != nil {
			log.Info(ctx, "node not closing as expected", logging.NewKV("Error", err))
		}
	}
}

func randomNetworkingConfig() *config.Config {
	p2pPort := rand.Intn(999) + 9000
	tcpPort := rand.Intn(999) + 9000
	cfg := config.DefaultConfig()
	cfg.Net.P2PAddress = fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", p2pPort)
	cfg.Net.RPCAddress = fmt.Sprintf("0.0.0.0:%d", tcpPort)
	cfg.Net.TCPAddress = fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", tcpPort)
	return cfg
}
