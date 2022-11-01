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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"

	"golang.org/x/crypto/acme/autocert"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/errors"
	"github.com/sourcenetwork/defradb/logging"
)

const (
	// These constants are best effort durations that fit our current API
	// and possibly prevent from running out of file descriptors.
	// readTimeout  = 5 * time.Second
	// writeTimeout = 10 * time.Second
	// idleTimeout  = 120 * time.Second

	// Temparily disabling timeouts until [this proposal](https://github.com/golang/go/issues/54136) is merged.
	// https://github.com/sourcenetwork/defradb/issues/927
	readTimeout  = 0
	writeTimeout = 0
	idleTimeout  = 0
)

// Server struct holds the Handler for the HTTP API.
type Server struct {
	options     serverOptions
	listener    net.Listener
	broker      *broker
	certManager *autocert.Manager

	http.Server
}

type serverOptions struct {
	// list of allowed origins for CORS.
	allowedOrigins []string
	// ID of the server node.
	peerID string
	// when the value is present, the server will run with tls
	tls client.Option[tlsOptions]
	// root directory for the node config.
	rootDir string
}

type tlsOptions struct {
	// Public key for TLS. Ignored if domain is set.
	pubKey string
	// Private key for TLS. Ignored if domain is set.
	privKey string
	// email address for the CA to send problem notifications (optional)
	email string
	// The domain to associate the certificate.
	domain string
	// specify the tls port
	port string
}

// NewServer instantiates a new server with the given http.Handler.
func NewServer(db client.DB, options ...func(*Server)) *Server {
	brk := newBroker()

	srv := &Server{
		Server: http.Server{
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		},
		broker: brk,
	}

	for _, opt := range append(options, DefaultOpts()) {
		opt(srv)
	}

	srv.Handler = newHandler(db, brk, srv.options)

	return srv
}

func newHTTPRedirServer(m *autocert.Manager) *Server {
	srv := &Server{
		Server: http.Server{
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		},
	}

	srv.Addr = ":80"
	srv.Handler = m.HTTPHandler(nil)

	return srv
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

		// If the address is not localhost, we check to see if it's a valid IP address.
		// If it's not a valid IP, we assume that it's a domain name to be used with TLS.
		if !strings.HasPrefix(addr, "localhost:") && !strings.HasPrefix(addr, ":") {
			ip := net.ParseIP(addr)
			if ip == nil {
				tlsOpt := s.options.tls.Value()
				tlsOpt.domain = addr
				s.options.tls = client.Some(tlsOpt)
			}
		}
	}
}

func WithCAEmail(email string) func(*Server) {
	return func(s *Server) {
		tlsOpt := s.options.tls.Value()
		tlsOpt.email = email
		s.options.tls = client.Some(tlsOpt)
	}
}

func WithPeerID(id string) func(*Server) {
	return func(s *Server) {
		s.options.peerID = id
	}
}

func WithRootDir(rootDir string) func(*Server) {
	return func(s *Server) {
		s.options.rootDir = rootDir
	}
}

func WithSelfSignedCert(pubKey, privKey string) func(*Server) {
	return func(s *Server) {
		tlsOpt := s.options.tls.Value()
		tlsOpt.pubKey = pubKey
		tlsOpt.privKey = privKey
		s.options.tls = client.Some(tlsOpt)
	}
}

func WithTLSPort(port int) func(*Server) {
	return func(s *Server) {
		tlsOpt := s.options.tls.Value()
		tlsOpt.port = fmt.Sprintf(":%d", port)
		s.options.tls = client.Some(tlsOpt)
	}
}

// Listen creates a new net.Listener and saves it on the receiver.
func (s *Server) Listen(ctx context.Context) error {
	var err error
	if s.options.tls.HasValue() {
		return s.listenWithTLS(ctx)
	}

	lc := net.ListenConfig{}
	s.listener, err = lc.Listen(ctx, "tcp", s.Addr)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (s *Server) listenWithTLS(ctx context.Context) error {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// We only allow cipher suites that are marked secure
		// by ssllabs
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	addr := s.Addr

	if s.options.tls.Value().domain != "" {
		addr = s.options.tls.Value().port

		certCache := path.Join(s.options.rootDir, "autocerts")

		log.FeedbackInfo(
			ctx,
			"Generating auto certificate",
			logging.NewKV("Domain", s.options.tls.Value().domain),
			logging.NewKV("Cert cache", certCache),
		)

		m := &autocert.Manager{
			Cache:      autocert.DirCache(certCache),
			Prompt:     autocert.AcceptTOS,
			Email:      s.options.tls.Value().email,
			HostPolicy: autocert.HostWhitelist(s.options.tls.Value().domain),
		}

		config.GetCertificate = m.GetCertificate

		// We set manager on the server instance to later start
		// a redirection server.
		s.certManager = m
	} else {
		// When not using auto cert, we create a self signed certificate
		// with the provided public and prive keys.
		log.FeedbackInfo(ctx, "Generating self signed certificate")

		cert, err := tls.LoadX509KeyPair(
			path.Join(s.options.rootDir, s.options.tls.Value().privKey),
			path.Join(s.options.rootDir, s.options.tls.Value().pubKey),
		)
		if err != nil {
			return errors.WithStack(err)
		}

		config.Certificates = []tls.Certificate{cert}
	}

	var err error
	s.listener, err = tls.Listen("tcp", addr, config)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// Run calls Serve with the receiver's listener
func (s *Server) Run(ctx context.Context) error {
	if s.listener == nil {
		return errNoListener
	}

	go s.broker.listen(ctx)

	if s.certManager != nil {
		// When using TLS it's important to redirect http requests to https
		go func() {
			srv := newHTTPRedirServer(s.certManager)
			err := srv.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Info(ctx, "Something went wrong with the redirection server", logging.NewKV("Error", err))
			}
		}()
	}
	return s.Serve(s.listener)
}
