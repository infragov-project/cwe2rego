class { 'apache':
  default_mods => false,
  mpm_module   => 'prefork',
  default_vhost => false,
}

apache::vhost { 'insecure.example.com':
  port          => '80', # CWE-319: Configures Apache to listen on port 80 (HTTP) without SSL
  docroot       => '/var/www/insecure_app',
  servername    => 'insecure.example.com',
  # No SSL configuration is provided, making it an HTTP-only vhost
}