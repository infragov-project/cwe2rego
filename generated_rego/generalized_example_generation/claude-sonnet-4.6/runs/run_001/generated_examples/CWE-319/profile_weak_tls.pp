class { 'profile::webserver':
  min_tls_version => 'TLS1_0',
  ssl_enabled     => false,
}