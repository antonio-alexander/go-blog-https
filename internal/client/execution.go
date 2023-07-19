package client

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

func getCertificates(c *Configuration) ([]tls.Certificate, error) {
	if c.CertFile == "" || c.KeyFile == "" {
		return []tls.Certificate{}, nil
	}
	bytesCert, err := os.ReadFile(c.CertFile)
	if err != nil {
		return nil, err
	}
	bytesKey, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(bytesCert, bytesKey)
	if err != nil {
		return nil, err
	}
	return []tls.Certificate{certificate}, nil
}

func getCaCert(c *Configuration) (*x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	if c.CaCertificate != "" {
		bytes, err := os.ReadFile(c.CaCertificate)
		if err != nil {
			return nil, err
		}
		caCertPool.AppendCertsFromPEM(bytes)
	}
	return caCertPool, nil
}

func getTlsConfig(c *Configuration) (*tls.Config, error) {
	caCertPool, err := getCaCert(c)
	if err != nil {
		return nil, err
	}
	certificates, err := getCertificates(c)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		// TLS versions below 1.2 are considered insecure
		// see https://www.rfc-editor.org/rfc/rfc7525.txt for details
		MinVersion:   tls.VersionTLS12,
		RootCAs:      caCertPool,
		Certificates: certificates,
	}, nil
}
