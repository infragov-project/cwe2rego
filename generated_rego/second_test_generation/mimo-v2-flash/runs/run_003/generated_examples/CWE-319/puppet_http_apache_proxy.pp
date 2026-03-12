# This example assumes the 'apache' module is installed and configured.
# It configures an Apache vhost on port 80 that proxies requests to an
# unencrypted HTTP backend application.
apache::vhost { 'app.example.com':
  port      => '80',
  docroot   => '/var/www/html/app',
  # Proxy sensitive API calls to an unencrypted backend channel
  proxypass => [
    { path => '/api', url => 'http://backend-service.internal:8080/api' },
    { path => '/admin', url => 'http://legacy-admin-panel.internal:8081/admin' },
  ],
  require   => Class['apache'],
}
