# puppet_nginx_weak_tls.pp
# Assumes 'nginx' module is installed and configured

class { 'nginx': }

nginx::resource::server { 'weak_example.com':
  ensure              => 'present',
  listen_port         => 443,
  ssl                 => true,
  ssl_certificate     => '/etc/nginx/ssl/weak_example.com.crt',
  ssl_certificate_key => '/etc/nginx/ssl/weak_example.com.key',
  ssl_protocols       => ['TLSv1', 'TLSv1.1'], # CWE-326: Deprecated or Insecure Transport Protocols (TLS 1.0, TLS 1.1)
  ssl_ciphers         => 'HIGH:!aNULL:!MD5:!RC4',
  index_files         => ['index.html', 'index.htm'],
  location_aliases    => {
    '/' => '/var/www'
  },
}
