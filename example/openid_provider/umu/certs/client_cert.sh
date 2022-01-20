openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout client.key -out client.crt -subj '/CN=127.0.0.1' \
  -extensions san -config example.conf