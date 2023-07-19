package server

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
)

func getClientAuthType(s string) tls.ClientAuthType {
	//KIM: there are other cert types, but for the most part,
	// these two are the only functional ones
	switch strings.ToLower(s) {
	default:
		return tls.NoClientCert
	case "RequireAndVerifyClientCert":
		return tls.RequireAndVerifyClientCert
	}
}

func getCertificates(c *Configuration) ([]tls.Certificate, error) {
	var certificates []tls.Certificate

	if c.CertFile != "" && c.KeyFile != "" {
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
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

func getCaCert(c *Configuration, clientAuthType tls.ClientAuthType) (*x509.CertPool, error) {
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
	if !c.HttpsEnabled {
		return &tls.Config{}, nil
	}
	clientAuthType := getClientAuthType(c.ClientAuthType)
	caCertPool, err := getCaCert(c, clientAuthType)
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
		Certificates: certificates,
		ClientCAs:    caCertPool,
		ServerName:   c.CertificateServerName,
		ClientAuth:   clientAuthType,
	}, nil
}
