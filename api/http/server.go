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
	"net"
	"net/http"

	"github.com/sourcenetwork/defradb/client"
)

// Server struct holds the Handler for the HTTP API.
type Server struct {
	options  serverOptions
	listener net.Listener

	http.Server
}

type serverOptions struct {
	allowedOrigins []string
	peerID         string
}

// NewServer instantiates a new server with the given http.Handler.
func NewServer(db client.DB, options ...func(*Server)) *Server {
	svr := &Server{}

	for _, opt := range append(options, DefaultOpts()) {
		opt(svr)
	}

	svr.Server.Handler = newHandler(db, svr.options)

	return svr
}

func DefaultOpts() func(*Server) {
	return func(s *Server) {
		if s.Addr == "" {
			s.Addr = "localhost:9181"
		}
	}
}

func WithAllowedOrigins(origins ...string) func(*Server) {
	return func(s *Server) {
		s.options.allowedOrigins = append(s.options.allowedOrigins, origins...)
	}
}

func WithAddress(addr string) func(*Server) {
	return func(s *Server) {
		s.Addr = addr
	}
}

func WithPeerID(id string) func(*Server) {
	return func(s *Server) {
		s.options.peerID = id
	}
}

// Listen creates a new net.Listener and saves it on the receiver.
func (s *Server) Listen(ctx context.Context) error {
	lc := net.ListenConfig{}
	l, err := lc.Listen(ctx, "tcp", s.Addr)
	if err != nil {
		return err
	}
	s.listener = l
	return nil
}

// Run calls Serve with the receiver's listener
func (s *Server) Run() error {
	if s.listener == nil {
		return errNoListener
	}
	return s.Serve(s.listener)
}
