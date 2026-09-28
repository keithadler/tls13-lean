# TLS server test identity

`server_cert.pem` is the Ed25519 localhost certificate used by the pure
client/server handshake regression. It matches
`grpc-lean/Test/Fixtures/Tls/server_cert.pem`, so the reusable TLS core and its
gRPC consumer exercise the same identity.

The matching 32-byte Ed25519 test seed is intentionally embedded in
`Test/TlsServerInteropTest.lean`; it is public test data and must never be used
outside tests.

The equivalent OpenSSL 3 construction is:

```sh
openssl genpkey -algorithm ED25519 -out server_key.pem
openssl req -new -x509 -key server_key.pem -days 3650 \
  -subj /CN=localhost \
  -addext basicConstraints=critical,CA:TRUE \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
  -out server_cert.pem
```

The committed certificate is valid from 2026-07-19 through 2036-07-16.

`ecdsa_server_cert.pem` is a self-signed P-256 localhost certificate
(KeyUsage `digitalSignature`, EKU `serverAuth`) for the server's
`ecdsa_secp256r1_sha256` CertificateVerify. Its 32-byte private scalar is
embedded in `Test/TlsServerInteropTest.lean`, again public test data only. It
was made with

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout key.pem -out ecdsa_server_cert.pem -days 36500 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost \
  -addext keyUsage=critical,digitalSignature -addext extendedKeyUsage=serverAuth
```

and is valid from 2026-09-28 through 2126-09-04.
