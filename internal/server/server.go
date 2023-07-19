package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
)

type Server struct {
	sync.WaitGroup
	sync.RWMutex
	*http.Server
}

func New() *Server {
	return &Server{
		Server: &http.Server{
			TLSConfig: &tls.Config{
				// TLS versions below 1.2 are considered insecure
				// see https://www.rfc-editor.org/rfc/rfc7525.txt for details
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{},
				ClientCAs:    &x509.CertPool{},
				ClientAuth:   tls.NoClientCert,
			},
		},
	}
}

func (s *Server) Configure(c *Configuration) error {
	tlsConfig, err := getTlsConfig(c)
	if err != nil {
		return err
	}
	s.Server.Addr = fmt.Sprintf("%s:%s", c.Address, c.Port)
	s.Server.ReadTimeout = c.ReadTimeout
	s.Server.WriteTimeout = c.WriteTimeout
	s.Server.TLSConfig = tlsConfig
	return nil
}
