class profile::webserver {
  nginx::resource::server { 'myapp.example.com':
    listen_port       => 80,
    server_name       => ['myapp.example.com', 'www.myapp.example.com'],
    proxy             => 'http://127.0.0.1:8080',
    ssl               => false,
    ssl_cert          => undef,
    ssl_key           => undef,
    require_ssl       => false,
    rewrite_to_https  => false,
  }

  nginx::resource::upstream { 'app_backend':
    members => {
      'backend1:8080' => { weight => 1 },
      'backend2:8080' => { weight => 1 },
    },
  }
}
