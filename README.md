# go-blog-https (github.com/antonio-alexander/go-blog-https)

The goal of this repository is to describe how to use https with golang, both as a client and as a server. I want to answer the following questions:

- How does https work with browsers interacting with https servers
- How does https work with clients/apis interacting with https servers
- How does https prevent eavesdropping or man-in-the-middle attacks?
- How can the server/client manage certificates
- How can you generate a certificate

## Helpful Links

- [https://medium.com/rungo/secure-https-servers-in-go-a783008b36da](https://medium.com/rungo/secure-https-servers-in-go-a783008b36da)
- [https://youngkin.github.io/post/gohttpsclientserver/](https://youngkin.github.io/post/gohttpsclientserver/)
- [https://linuxize.com/post/creating-a-self-signed-ssl-certificate/](https://linuxize.com/post/creating-a-self-signed-ssl-certificate/)
- [https://devopscube.com/create-self-signed-certificates-openssl/](https://devopscube.com/create-self-signed-certificates-openssl/)
- [https://cheapsslsecurity.com/blog/fix-err-cert-common-name-invalid/](https://cheapsslsecurity.com/blog/fix-err-cert-common-name-invalid/)
- [https://github.com/joneskoo/http2-keylog](https://github.com/joneskoo/http2-keylog)
- [https://www.smashingmagazine.com/2017/06/guide-switching-http-https/](https://www.smashingmagazine.com/2017/06/guide-switching-http-https/)
- [https://crypto.stackexchange.com/questions/43697/what-are-the-differences-between-pem-csr-key-crt-and-other-such-file-exte](https://crypto.stackexchange.com/questions/43697/what-are-the-differences-between-pem-csr-key-crt-and-other-such-file-exte)
- [https://manuals.gfi.com/en/kerio/connect/content/server-configuration/ssl-certificates/adding-trusted-root-certificates-to-the-server-1605.html](https://manuals.gfi.com/en/kerio/connect/content/server-configuration/ssl-certificates/adding-trusted-root-certificates-to-the-server-1605.html)

## Getting Started

## Generating Certificates/Keys

> Personally, I hate that it makes a lot more sense to use [certstrap](https://github.com/square/certstrap) rather than doing it manually using openssl. cerstrap obfusicates some of the process to make it easier, but the focus is to understand how to setup https servers/clients and not specifically how to generate certificates

The most difficult problem about this entire https effort is generating certificates and keys. In practice (if you had an actual website rather than this proof of concept); you'd pay a Certificate Authority to generate an SSL for you and that CA would then be trusted by all browsers. 

Because this is a proof of concept, and we just want to "simulate" it working, we can do the same thing (and for free) by being our own CA. By being own own CA and generating certificate(s) we can install them in a browser and ensure that they are "trusted". We'll genreate "three" sets of certificates:

- a set for the CA (Certificate Authority)
- a set for the HTTPS server
- a set for the HTTPS client

Certificates have a chain such that the https private keys are associated with the root/CA authority, adn the client certificates are also associated with the server. This happens behind the scenes and would probably be a bit more obvious with the openssl commands, but for purposes of this repo, _take it for granted_.

> In the makefile we'll offer two methods, one using openssl directly and another using certutil; because certutil reads easier, we'll reference that within this document and will consider openssl being "out of scope"

To generate the required certificates using certuil we'll execute the following steps:

1. Install certstrap

```sh
go install github.com/sqaure/certstrap@v1.3.0
```

2. Generate certificates/keys for our Certificate Authority

```sh
certstrap --depot-path ./certs init --common-name "ca" --passphrase=""
```

3. Generate private keys and csr config for the server

```sh
certstrap --depot-path ./certs request-cert --domain "localhost" --passphrase="" -key ./certs/server.key -csr ./certs/server.csr
```

4. Generate private keys and csr config for the client

```sh
certstrap --depot-path ./certs request-cert --domain "client" --passphrase="" -key ./certs/client.key -csr ./certs/client.csr
```

5. Generate certificate signed by our CA for the server

```sh
certstrap --depot-path ./certs sign localhost --passphrase="" --CA "ca" --csr ./certs/server.csr --cert ./certs/server.crt
```

6. Generate certificate signed by our CA for the client

```sh
certstrap --depot-path ./certs sign client --passphrase="" --CA "ca" --csr ./certs/client.csr --cert ./certs/client.crt
```

7. Register this root certificate (locally); this is what tells the browser to trust

```sh
sudo cp ./certs/ca.crt /usr/local/share/ca-certificates/ca.crt
sudo update-ca-certificates
```

> Alternatively, you could interact with [chrome](chrome://settings/certificates) (or your browser of choice) to import the trusted keys/certificates

## Server

Fortunately, once you've generated the keys and certificates, ACTUALLY configuring the webserver to use TLS is rather anti-climatic. TLS is configured through TLS configuration within the http server. See the following:

```go
httpServer := &http.Server{
    TLSConfig: &tls.Config{
    	// TLS versions below 1.2 are considered insecure
    	// see https://www.rfc-editor.org/rfc/rfc7525.txt for details
    	MinVersion:   tls.VersionTLS12,
    	Certificates: []tls.Certificate{}, // this is where you'd add the public/private key
    	ClientCAs:    &x509.CertPool{},    // this is where you'd add the CA cert
    	ClientAuth:   tls.NoClientCert,    // this is where you configure client cert requirements
    },
}
```

There's a ton of ways to implement the code that actually genreates the tls configuration (see: [./internal/server/execution.go](./internal/server/execution.go)); I'll copy+pasta some of the code below and provide some suggestions as to why I chose these solutions:

```go
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
```

<!-- TODO: add some color commentary about the code above -->

I think the thing that's probably the most confusing is the client authentication type; at a glance it looks like you have a myriad of options to choose from, but functionally you only have two: (A) the server doesn't require clients have a valid cert and (B) the server requires that connected clients have a valid cert. 

This is an except from [https://pkg.go.dev/crypto/tls](https://pkg.go.dev/crypto/tls):

```go
const (
	// NoClientCert indicates that no client certificate should be requested
	// during the handshake, and if any certificates are sent they will not
	// be verified.
	NoClientCert ClientAuthType = iota
	// RequestClientCert indicates that a client certificate should be requested
	// during the handshake, but does not require that the client send any
	// certificates.
	RequestClientCert
	// RequireAnyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one certificate is required to be
	// sent by the client, but that certificate is not required to be valid.
	RequireAnyClientCert
	// VerifyClientCertIfGiven indicates that a client certificate should be requested
	// during the handshake, but does not require that the client sends a
	// certificate. If the client does send a certificate it is required to be
	// valid.
	VerifyClientCertIfGiven
	// RequireAndVerifyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one valid certificate is required
	// to be sent by the client.
	RequireAndVerifyClientCert
)
```

I think there are some academic reasons for some of the different client authentication types, but practically the certificate either matters or doesn't matter: why go through the trouble of having the client configure a cert if you're not gonna require it be valid. 

## Client 

The client, similarly, is also anti-climatic once you've generated the certificates for the CA and the public/private keys. I think the most annoying part about configuring the client for https come from:

- ensuring that your uri's include http or https as needed
- re-purposing tls.Config{} for use in clients isn't quite the same as servers

The first, fairly simple is to ensure the clients uri's make sense if you're using https or http. By NOT doing this, you may receive the following error:

```
Client sent an HTTP request to an HTTPS server.
```

This is as advertised, if you attempt to connect to a server with SSL enabled, regardless of the port, and you use http instead of https, you'll get the error above. In addition, if no port is given https assumes port 443 and http assumes port 80. See the code for this below:

```go
func (c *client) Configure(config *Configuration) error {
	c.address = config.Address + ":" + config.Port
	if config.Port == "" {
		c.address = config.Address
	}
	switch {
	default:
		c.address = "http://" + c.address
	case config.HttpsEnabled:
		c.address = "https://" + c.address
		tlsConfig, err := getTlsConfig(config)
		if err != nil {
			return err
		}
		c.Client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	c.Client.Timeout = config.Timeout
	return nil
}
```

In the code above, we avoid having to constantly determine what the address should be in each of our endpoints by doing it once in the configure function. We handle the logic as to whether or not the port is defined, and then depending on https being enabled, we'll apply the appropriate prefix (http:// or https://).

The configuration for tls is similar to the configuration for the server except that some of the fields have different purposes:

```go
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
```

In contrast to the server, you'll use the CA certificate as the root ca and you'll import your client certificates within the certificates array; that's really the only difference. If you don't do it this way, you'll get ambiguous 400 errors when you're using the right certificates (but in the wrong place).

## Frequently Asked Questions (FAQ)

These are a handful of questions I asked myself while working on this proof of concept; they may help you out as you attempt an implementation on your own or simply may satisfy your curiosity. I'm on a time crunch, so a lot of the content here isn't as researched as I'd like it to be so expect me to be wrong or to have a less developed opinion about some of these.

How do you solve this error:

```sh
Get "https://localhost:8080": tls: failed to verify certificate: x509: certificate signed by unknown authority
```

> this was a weird error, I got it because I'd configured the client to use the CA certificate but i'd put it in the certificates slice rather than the RootCAs member. It generally means there's something wrong with the Root CA certificate; could mean that it's not signed properly too even if the cert is _valid_.

What's the point of client certificates?

> I'm not 100% sure, but I think there's room for the server to be able to invidiaully identify client certificates for authentication purposes; in the things that I read it seemed possible to individually authenticate certain clients based on their certificate and not just that they 
were signed by a known Certificate Authority

What are my options for debugging?

> This was a little strange since security by default is relatively obscure when it comes to error logging. I did stumble onto a github repo [https://github.com/joneskoo/http2-keylog](https://github.com/joneskoo/http2-keylog) that seemed to indicate that you could use this code along with wireshark (?) to debug tls handshake issues. Otherwise it seems like there are some functions you can inject into the tls.Config{} that will allow you to add some logging, but it doesn't seem like it was really built for it
