nginx::resource::server { 'example.com':
  port   => 80,
  ssl    => false,
  listen => ['80'],
}