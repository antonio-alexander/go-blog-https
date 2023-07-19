package server

import (
	"strconv"
	"time"
)

const (
	defaultCertFile              string        = ""
	defaultKeyFile               string        = ""
	defaultCaCertificate         string        = ""
	defaultAddress               string        = ""
	defaulHttpPort               string        = "8080"
	defaulHttpsEnabled           bool          = false
	defaultReadTimeout           time.Duration = time.Minute
	defaultWriteTimeout          time.Duration = time.Minute
	defaultCertificateServerName string        = "go-blog-https"
	defaultClientAuthType        string        = "NoClientCert"
)

const (
	CERT_FILE               string = "CERT_FILE"
	KEY_FILE                string = "KEY_FILE"
	HTTPS_ENABLED           string = "HTTPS_ENABLED"
	HTTP_ADDRESS            string = "HTTP_ADDRESS"
	HTTP_PORT               string = "HTTP_PORT"
	READ_TIMEOUT            string = "READ_TIMEOUT"
	WRITE_TIMEOUT           string = "WRITE_TIMEOUT"
	CERTIFICATE_SERVER_NAME string = "CERTIFICATE_SERVER_NAME"
	CLIENT_AUTH_TYPE        string = "CLIENT_AUTH_TYPE"
	CA_CERTIFICATE          string = "CA_CERTIFICATE"
)

type Configuration struct {
	CertFile              string
	KeyFile               string
	Address               string
	Port                  string
	CertificateServerName string
	HttpsEnabled          bool
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	ClientAuthType        string
	CaCertificate         string
}

func NewConfiguration() *Configuration {
	return &Configuration{
		CertFile:              defaultCertFile,
		KeyFile:               defaultKeyFile,
		Address:               defaultAddress,
		Port:                  defaulHttpPort,
		CertificateServerName: defaultCertificateServerName,
		HttpsEnabled:          defaulHttpsEnabled,
		ReadTimeout:           defaultReadTimeout,
		WriteTimeout:          defaultWriteTimeout,
		ClientAuthType:        defaultClientAuthType,
		CaCertificate:         defaultCaCertificate,
	}
}

func (c *Configuration) FromEnvs(envs map[string]string) {
	if s := envs[CERT_FILE]; s != "" {
		c.CertFile = s
	}
	if s := envs[KEY_FILE]; s != "" {
		c.KeyFile = s
	}
	if s := envs[HTTP_PORT]; s != "" {
		c.Port = s
	}
	if s := envs[HTTP_ADDRESS]; s != "" {
		c.Address = s
	}
	if s := envs[CLIENT_AUTH_TYPE]; s != "" {
		c.ClientAuthType = s
	}
	if s := envs[CA_CERTIFICATE]; s != "" {
		c.CaCertificate = s
	}
	if s := envs[CERTIFICATE_SERVER_NAME]; s != "" {
		c.CertificateServerName = s
	}
	if s := envs[HTTPS_ENABLED]; s != "" {
		c.HttpsEnabled, _ = strconv.ParseBool(envs[HTTPS_ENABLED])
	}
	if s := envs[READ_TIMEOUT]; s != "" {
		i, _ := strconv.ParseInt(s, 10, 64)
		c.ReadTimeout = time.Duration(i) * time.Minute
	}
	if s := envs[WRITE_TIMEOUT]; s != "" {
		i, _ := strconv.ParseInt(s, 10, 64)
		c.WriteTimeout = time.Duration(i) * time.Minute
	}
}
