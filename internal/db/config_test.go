// Copyright 2024 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithUpdateEvents(t *testing.T) {
	d := &db{}
	WithUpdateEvents()(d)
	assert.NotNil(t, d.events)
}

func TestWithMaxRetries(t *testing.T) {
	d := &db{}
	WithMaxRetries(10)(d)
	assert.True(t, d.maxTxnRetries.HasValue())
	assert.Equal(t, 10, d.maxTxnRetries.Value())
}
