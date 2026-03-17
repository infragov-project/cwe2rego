x509_cert { '/etc/pki/tls/certs/weak-cert.pem':
  ensure        => 'present',
  cert_path     => '/etc/pki/tls/certs/weak-cert.pem',
  key_path      => '/etc/pki/tls/private/weak-key.pem',
  password      => 'secret',
  key_length    => 1024, # CWE-326: Weak RSA key size below 2048 bits
  lifetime      => '365',
  country       => 'US',
  organization  => 'Example',
  commonname    => 'weak.example.com',
  days_valid    => 365,
  subject_alt_names => 'DNS:weak.example.com,IP:127.0.0.1',
}