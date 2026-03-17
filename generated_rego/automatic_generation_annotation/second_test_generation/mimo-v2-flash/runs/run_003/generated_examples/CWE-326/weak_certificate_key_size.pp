# This defines an X.509 certificate with an inadequate RSA key length.
# This is a hypothetical `tls::certificate` type for illustrative purposes.

tls::certificate { 'server-cert':
  ensure     => present,
  domain     => 'weak.example.com',
  # Explicitly set weak key size
  key_size   => 1024, # Inadequate key length for RSA
  algorithm  => 'RSA',
  chain_path => '/etc/pki/tls/certs/ca-bundle.crt',
  key_path   => '/etc/pki/tls/private/server.key',
  cert_path  => '/etc/pki/tls/certs/server.crt',
}
