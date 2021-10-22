// Copyright 2020 Source Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.
package simple_test

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/db/tests"
)

var userSchema = (`
	type user {
		name: String
		age: Int
		points: Float
		verified: Boolean
	}
`)

func ExecuteTestCase(t *testing.T, test testUtils.QueryTestCase) {
	testUtils.ExecuteQueryTestCase(t, userSchema, []string{"user"}, test)
}
