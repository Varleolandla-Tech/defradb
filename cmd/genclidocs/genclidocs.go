// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package main

import (
	"context"
	"flag"
	"os"

	"github.com/sourcenetwork/defradb/cli"
	"github.com/sourcenetwork/defradb/logging"

	"github.com/spf13/cobra/doc"
)

var log = logging.MustNewLogger("defra.genclidocs")

func main() {
	path := flag.String("o", "docs/cmd", "path to write the cmd docs to")
	flag.Parse()
	err := os.MkdirAll(*path, os.ModePerm)
	if err != nil {
		log.FatalE(context.Background(), "Creating the filesystem path failed", err)
	}
	err = doc.GenMarkdownTree(cli.RootCmd, *path)
	if err != nil {
		log.FatalE(context.Background(), "Generating cmd docs failed", err)
	}
}
