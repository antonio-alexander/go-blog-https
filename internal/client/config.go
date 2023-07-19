package client

import (
	"flag"
	"strconv"
	"time"
)

const (
	defaultCertFile              string        = ""
	defaultKeyFile               string        = ""
	defaultHttpPort              string        = "8080"
	defaultAddress               string        = "localhost"
	defaultHttpsEnabled          bool          = false
	defaultTimeout               time.Duration = time.Minute
	defaultCertificateServerName string        = "go-blog-https"
	defaultCaCertificate         string        = ""
)

const (
	CERT_FILE               string = "CERT_FILE"
	KEY_FILE                string = "KEY_FILE"
	HTTPS_ENABLED           string = "HTTPS_ENABLED"
	HTTP_ADDRESS            string = "HTTP_ADDRESS"
	HTTP_PORT               string = "HTTP_PORT"
	TIMEOUT                 string = "TIMEOUT"
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
	Timeout               time.Duration
	CaCertificate         string
}

func NewConfiguration() *Configuration {
	return &Configuration{
		CertFile:              defaultCertFile,
		KeyFile:               defaultKeyFile,
		Address:               defaultAddress,
		Port:                  defaultHttpPort,
		CertificateServerName: defaultCertificateServerName,
		HttpsEnabled:          defaultHttpsEnabled,
		Timeout:               defaultTimeout,
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
	if s := envs[CA_CERTIFICATE]; s != "" {
		c.CaCertificate = s
	}
	if s := envs[CERTIFICATE_SERVER_NAME]; s != "" {
		c.CertificateServerName = s
	}
	if s := envs[HTTPS_ENABLED]; s != "" {
		c.HttpsEnabled, _ = strconv.ParseBool(envs[HTTPS_ENABLED])
	}
	if s := envs[TIMEOUT]; s != "" {
		i, _ := strconv.ParseInt(s, 10, 64)
		c.Timeout = time.Duration(i) * time.Minute
	}
}

func (c *Configuration) FromCli(args []string) {
	var timeout int

	flag.StringVar(&c.CertFile, "cert-file", defaultCertFile, "")
	flag.StringVar(&c.KeyFile, "key-file", defaultKeyFile, "")
	flag.StringVar(&c.Address, "address", defaultAddress, "")
	flag.StringVar(&c.Port, "port", defaultHttpPort, "")
	flag.StringVar(&c.CertificateServerName, "cert-server-name", defaultCertificateServerName, "")
	flag.BoolVar(&c.HttpsEnabled, "https-enabled", defaultHttpsEnabled, "")
	flag.IntVar(&timeout, "timeout", int(defaultTimeout/time.Second), "")
	flag.StringVar(&c.CaCertificate, "ca-cert", defaultCaCertificate, "")
	flag.Parse()
	c.Timeout = time.Second * time.Duration(timeout)
}
