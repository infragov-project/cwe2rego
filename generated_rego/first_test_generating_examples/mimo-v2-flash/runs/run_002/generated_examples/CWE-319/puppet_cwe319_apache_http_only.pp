# Puppet manifest to configure an Apache virtual host for HTTP only

class apache_cwe319_http_only {
  class { 'apache': }

  apache::vhost { 'insecure.example.com':
    port    => '80', # CWE-319: Configuring an Apache virtual host to listen only on port 80 (HTTP).
    docroot => '/var/www/insecure',
    options => ['+Indexes', '+FollowSymLinks'],
    # ensure            => 'present', # This is implied by default
  }

  file { '/var/www/insecure/index.html':
    ensure  => file,
    content => '<h1>This site might transmit data in the clear!</h1>',
    owner   => 'www-data',
    group   => 'www-data',
    mode    => '0644',
  }
}
