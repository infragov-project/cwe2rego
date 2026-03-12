# Assumes apache module is installed, e.g., puppetlabs/apache
class { 'apache': }

apache::vhost { 'app.example.com':
  port            => '443',
  docroot         => '/var/www/html',
  ssl             => true,
  ssl_cipher_suite => 'TLSv1.0:!SSLv2:!SSLv3', # Explicitly weak cipher suite
  ssl_protocol    => 'TLSv1.0 TLSv1.1', # CWE-319: Weak TLS versions explicitly allowed
  ssl_cert        => '/etc/ssl/certs/app.example.com.crt',
  ssl_key         => '/etc/ssl/private/app.example.com.key',
}
