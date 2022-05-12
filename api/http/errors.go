// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package http

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
)

var env = os.Getenv("DEFRA_ENV")

type errorResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Stack   string `json:"stack,omitempty"`
}

func handleErr(ctx context.Context, rw http.ResponseWriter, err error, status int) {
	if status == http.StatusInternalServerError {
		log.ErrorE(ctx, http.StatusText(status), err)
	}

	sendJSON(
		ctx,
		rw,
		errorResponse{
			Status:  status,
			Message: http.StatusText(status),
			Stack:   formatError(err),
		},
		status,
	)
}

func formatError(err error) string {
	if strings.ToLower(env) == "dev" || strings.ToLower(env) == "development" {
		return fmt.Sprintf("[DEV] %+v\n", err)
	}
	return ""
}
