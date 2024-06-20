// Copyright 2024 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package identity

import (
	"github.com/cyware/ssi-sdk/crypto"
	"github.com/cyware/ssi-sdk/did/key"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/sourcenetwork/immutable"
)

// didProducer generates a did:key from a public key
type didProducer = func(crypto.KeyType, []byte) (*key.DIDKey, error)

// None specifies an anonymous actor.
var None = immutable.None[Identity]()

// Identity describes a unique actor.
type Identity struct {
	// PublicKey is the actor's public key.
	PublicKey *secp256k1.PublicKey
	// PrivateKey is the actor's private key.
	PrivateKey *secp256k1.PrivateKey
	// DID is the actor's unique identifier.
	//
	// The address is derived from the actor's public key,
	// using the did:key method
	DID string
}

// FromPrivateKey returns a new identity using the given private key.
func FromPrivateKey(privateKey *secp256k1.PrivateKey) (immutable.Option[Identity], error) {
	pubKey := privateKey.PubKey()
	did, err := DIDFromPublicKey(pubKey)
	if err != nil {
		return None, err
	}

	return immutable.Some(Identity{
		DID:        did,
		PublicKey:  pubKey,
		PrivateKey: privateKey,
	}), nil
}

// FromPublicKey returns a new identity using the given public key.
func FromPublicKey(publicKey *secp256k1.PublicKey) (immutable.Option[Identity], error) {
	did, err := DIDFromPublicKey(publicKey)
	if err != nil {
		return None, err
	}
	return immutable.Some(Identity{
		DID:       did,
		PublicKey: publicKey,
	}), nil
}

// DIDFromPublicKey returns a did:key generated from the the given public key.
func DIDFromPublicKey(publicKey *secp256k1.PublicKey) (string, error) {
	return didFromPublicKey(publicKey, key.CreateDIDKey)
}

// didFromPublicKey produces a did from a secp256k1 key and a producer function
func didFromPublicKey(publicKey *secp256k1.PublicKey, producer didProducer) (string, error) {
	bytes := publicKey.SerializeUncompressed()
	did, err := producer(crypto.SECP256k1, bytes)
	if err != nil {
		return "", newErrDIDCreation(err, "secp256k1", bytes)
	}
	return did.String(), nil
}
