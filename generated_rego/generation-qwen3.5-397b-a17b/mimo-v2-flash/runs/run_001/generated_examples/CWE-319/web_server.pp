class { 'apache::vhost':
  port    => 80,
  ssl     => false,
  docroot => '/var/www/html',
}
