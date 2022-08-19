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
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

var env = os.Getenv("DEFRA_ENV")

var (
	errNoListener = errors.New("cannot serve with no listener")
	errSchema     = errors.New("base must start with the http or https scheme")
)

// ErrorResponse is the GQL top level object holding error items for the response payload.
type ErrorResponse struct {
	Errors []ErrorItem `json:"errors"`
}

// ErrorItem hold an error message and extensions that might be pertinent to the request
type ErrorItem struct {
	Message    string     `json:"message"`
	Extensions extensions `json:"extensions,omitempty"`
}

type extensions struct {
	Status    int    `json:"status"`
	HTTPError string `json:"httpError"`
	Stack     string `json:"stack,omitempty"`
}

func handleErr(ctx context.Context, rw http.ResponseWriter, err error, status int) {
	if status == http.StatusInternalServerError {
		log.ErrorE(ctx, http.StatusText(status), err)
	}

	sendJSON(
		ctx,
		rw,
		ErrorResponse{
			Errors: []ErrorItem{
				{
					Message: err.Error(),
					Extensions: extensions{
						Status:    status,
						HTTPError: http.StatusText(status),
						Stack:     formatError(err),
					},
				},
			},
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
