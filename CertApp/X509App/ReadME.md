## CA Key and self-signed Certificate

>openssl genrsa -out cakey.pem 2048

>openssl req -new -x509 -key cakey.pem -out ca.pem