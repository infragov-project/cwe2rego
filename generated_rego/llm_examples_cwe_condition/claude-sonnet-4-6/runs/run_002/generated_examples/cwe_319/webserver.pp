class profile::webserver {
  class { 'apache':
    default_vhost => false,
    mpm_module    => 'prefork',
  }

  apache::vhost { 'app.example.com':
    servername => 'app.example.com',
    port       => '80',
    docroot    => '/var/www/html',
    ssl        => false,
    ssl_cert   => undef,
    ssl_key    => undef,
  }

  apache::vhost { 'api.example.com':
    servername => 'api.example.com',
    port       => '80',
    docroot    => '/var/www/api',
    ssl        => false,
  }
}
