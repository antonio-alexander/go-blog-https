
#!/usr/bin/bash

# generate root certificate and root private key
openssl req -x509 -sha256 -days 1 -nodes -newkey rsa:4096 \
    -keyout ./certs/root_ca.key -out ./certs/root_ca.crt \
    -subj "/CN=localhost"

# generate a server private key
openssl genrsa -out ./certs/server.key 4096

cat > ./certs/csr.conf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = California
L = San Fransisco
O = MLopsHub
OU = MlopsHub Dev
CN = localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = www.localhost
IP.1 = 192.168.1.5
IP.2 = 192.168.1.6

EOF

# generate a server csr from private key using the csr.conf
openssl req -new -key ./certs/server.key -out ./certs/server.csr -config ./certs/csr.conf

cat > ./certs/cert.conf <<EOF

authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost

EOF

# generate server certificate using the root ca (and server csr)
openssl x509 -req -in ./certs/server.csr -CA ./certs/root_ca.crt -CAkey ./certs/root_ca.key \
    -CAcreateserial -out ./certs/server.crt -days 1 -sha256 -extfile ./certs/cert.conf

# generate the client certificate using the root ca (and server csr)
openssl x509 -req -in ./certs/server.csr -CA ./certs/root_ca.crt -CAkey ./certs/root_ca.key \
    -CAcreateserial -out ./certs/client.crt -days 1 -sha256 -extfile ./certs/cert.conf