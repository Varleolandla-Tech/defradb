// Copyright 2023 Democratized Data Foundation
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

	"github.com/sourcenetwork/immutable"
	"golang.org/x/crypto/acme/autocert"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/config"
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

const (
	httpPort  = ":80"
	httpsPort = ":443"
)

// Server struct holds the Handler for the HTTP API.
type Server struct {
	options     ServerOptions
	listener    net.Listener
	certManager *autocert.Manager
	// address that is assigned to the server on listen
	address string

	http.Server
}

type ServerOptions struct {
	// AllowedOrigins is the list of allowed origins for CORS.
	AllowedOrigins []string
	// TLS enables https when the value is present.
	TLS immutable.Option[TLSOptions]
	// RootDirectory is the directory for the node config.
	RootDir string
	// Domain is the domain for the API (optional).
	Domain immutable.Option[string]
}

type TLSOptions struct {
	// PublicKey is the public key for TLS. Ignored if domain is set.
	PublicKey string
	// PrivateKey is the private key for TLS. Ignored if domain is set.
	PrivateKey string
	// Email is the address for the CA to send problem notifications (optional)
	Email string
	// Port is the tls port
	Port string
}

// NewServer instantiates a new server with the given http.Handler.
func NewServer(db client.DB, options ...func(*Server)) (*Server, error) {
	srv := &Server{
		Server: http.Server{
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		},
	}

	for _, opt := range append(options, DefaultOpts()) {
		opt(srv)
	}

	handler, err := NewHandler(db, srv.options)
	if err != nil {
		return nil, err
	}
	srv.Handler = handler
	return srv, nil
}

func newHTTPRedirServer(m *autocert.Manager) *Server {
	srv := &Server{
		Server: http.Server{
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		},
	}

	srv.Addr = httpPort
	srv.Handler = m.HTTPHandler(nil)

	return srv
}

// DefaultOpts returns the default options for the server.
func DefaultOpts() func(*Server) {
	return func(s *Server) {
		if s.Addr == "" {
			s.Addr = "localhost:9181"
		}
	}
}

// WithAllowedOrigins returns an option to set the allowed origins for CORS.
func WithAllowedOrigins(origins ...string) func(*Server) {
	return func(s *Server) {
		s.options.AllowedOrigins = append(s.options.AllowedOrigins, origins...)
	}
}

// WithAddress returns an option to set the address for the server.
func WithAddress(addr string) func(*Server) {
	return func(s *Server) {
		s.Addr = addr

		// If the address is not localhost, we check to see if it's a valid IP address.
		// If it's not a valid IP, we assume that it's a domain name to be used with TLS.
		if !strings.HasPrefix(addr, "localhost:") && !strings.HasPrefix(addr, ":") {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			ip := net.ParseIP(host)
			if ip == nil {
				s.Addr = httpPort
				s.options.Domain = immutable.Some(host)
			}
		}
	}
}

// WithCAEmail returns an option to set the email address for the CA to send problem notifications.
func WithCAEmail(email string) func(*Server) {
	return func(s *Server) {
		tlsOpt := s.options.TLS.Value()
		tlsOpt.Email = email
		s.options.TLS = immutable.Some(tlsOpt)
	}
}

// WithRootDir returns an option to set the root directory for the node config.
func WithRootDir(rootDir string) func(*Server) {
	return func(s *Server) {
		s.options.RootDir = rootDir
	}
}

// WithSelfSignedCert returns an option to set the public and private keys for TLS.
func WithSelfSignedCert(pubKey, privKey string) func(*Server) {
	return func(s *Server) {
		tlsOpt := s.options.TLS.Value()
		tlsOpt.PublicKey = pubKey
		tlsOpt.PrivateKey = privKey
		s.options.TLS = immutable.Some(tlsOpt)
	}
}

// WithTLS returns an option to enable TLS.
func WithTLS() func(*Server) {
	return func(s *Server) {
		tlsOpt := s.options.TLS.Value()
		tlsOpt.Port = httpsPort
		s.options.TLS = immutable.Some(tlsOpt)
	}
}

// WithTLSPort returns an option to set the port for TLS.
func WithTLSPort(port int) func(*Server) {
	return func(s *Server) {
		tlsOpt := s.options.TLS.Value()
		tlsOpt.Port = fmt.Sprintf(":%d", port)
		s.options.TLS = immutable.Some(tlsOpt)
	}
}

// Listen creates a new net.Listener and saves it on the receiver.
func (s *Server) Listen(ctx context.Context) error {
	var err error
	if s.options.TLS.HasValue() {
		return s.listenWithTLS(ctx)
	}

	lc := net.ListenConfig{}
	s.listener, err = lc.Listen(ctx, "tcp", s.Addr)
	if err != nil {
		return errors.WithStack(err)
	}

	// Save the address on the server in case the port was set to random
	// and that we want to see what was assigned.
	s.address = s.listener.Addr().String()

	return nil
}

func (s *Server) listenWithTLS(ctx context.Context) error {
	cfg := &tls.Config{
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
		ServerName: "DefraDB",
	}

	if s.options.Domain.HasValue() && s.options.Domain.Value() != "" {
		s.Addr = s.options.TLS.Value().Port

		if s.options.TLS.Value().Email == "" || s.options.TLS.Value().Email == config.DefaultAPIEmail {
			return ErrNoEmail
		}

		certCache := path.Join(s.options.RootDir, "autocerts")

		log.FeedbackInfo(
			ctx,
			"Generating auto certificate",
			logging.NewKV("Domain", s.options.Domain.Value()),
			logging.NewKV("Certificate cache", certCache),
		)

		m := &autocert.Manager{
			Cache:      autocert.DirCache(certCache),
			Prompt:     autocert.AcceptTOS,
			Email:      s.options.TLS.Value().Email,
			HostPolicy: autocert.HostWhitelist(s.options.Domain.Value()),
		}

		cfg.GetCertificate = m.GetCertificate

		// We set manager on the server instance to later start
		// a redirection server.
		s.certManager = m
	} else {
		// When not using auto cert, we create a self signed certificate
		// with the provided public and prive keys.
		log.FeedbackInfo(ctx, "Generating self signed certificate")

		cert, err := tls.LoadX509KeyPair(
			s.options.TLS.Value().PrivateKey,
			s.options.TLS.Value().PublicKey,
		)
		if err != nil {
			return NewErrFailedToLoadKeys(err, s.options.TLS.Value().PublicKey, s.options.TLS.Value().PrivateKey)
		}

		cfg.Certificates = []tls.Certificate{cert}
	}

	var err error
	s.listener, err = tls.Listen("tcp", s.Addr, cfg)
	if err != nil {
		return errors.WithStack(err)
	}

	// Save the address on the server in case the port was set to random
	// and that we want to see what was assigned.
	s.address = s.listener.Addr().String()

	return nil
}

// Run calls Serve with the receiver's listener.
func (s *Server) Run(ctx context.Context) error {
	if s.listener == nil {
		return ErrNoListener
	}

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

// AssignedAddr returns the address that was assigned to the server on calls to listen.
func (s *Server) AssignedAddr() string {
	return s.address
}
