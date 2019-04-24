#!/bin/bash

# Configuration files
# openssl-ca.cnf          - contains information for the CA certificate
# openssl-ca-sign.cnf     - add the signing information most important private key and certificate
# openssl-server.cnf      - no explanation needed
# openssl-server-sign.cnf - no explanation needed
# openssl-client.cnf      - no explanation needed
# openssl-badboy.cnf      - creates a certificate which should be rejected

# Create self signed CA certificate
openssl req -x509 -config openssl-ca.cnf -newkey rsa:2048 -sha256 -nodes -out cacert.pem -outform PEM
openssl x509 -in cacert.pem -text -noout |head -n 20

# Create client server certificates
openssl req -config openssl-server.cnf -newkey rsa:2048 -sha256 -nodes -out servercert.csr -outform PEM 
openssl req -config openssl-client.cnf -newkey rsa:2048 -sha256 -nodes -out clientcert.csr -outform PEM
openssl req -config openssl-badboy.cnf -newkey rsa:2048 -sha256 -nodes -out badboycert.csr -outform PEM

# Initialize database (?) for signed certificates
echo -n > index.txt
echo '01' > serial.txt
echo -n > index-ri.txt
echo '01' > serial-ri.txt

# Sign server certificate with CA private key
echo -e "y\ny\n" | openssl ca -config openssl-ca-sign.cnf -policy signing_policy -extensions signing_req -out servercert.pem -infiles servercert.csr
# Sign client certificate with server private key
echo -e "y\ny\n" | openssl ca -config openssl-ca-sign.cnf -policy signing_policy -extensions signing_req -out clientcert.pem -infiles clientcert.csr
echo -e "y\ny\n" | openssl ca -config openssl-ca-sign.cnf -policy signing_policy -extensions signing_req -out badboycert.pem -infiles badboycert.csr

# openssl x509 -in cacert.pem -text -noout
