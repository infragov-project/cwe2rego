class { 'apache::mod::ssl': }

apache::vhost { 'insecure_site':
  port            => 443,
  docroot         => '/var/www/html',
  ssl             => true,
  ssl_protocols   => ['SSLv3', 'TLSv1', 'TLSv1.1'],
  ssl_cipher_suite => 'HIGH:MEDIUM:!aNULL:!MD5',
}