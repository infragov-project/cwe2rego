class web_application (
  String  $app_name   = 'myapp',
  String  $app_domain = 'app.example.com',
  Integer $http_port  = 80,
) {

  class { 'nginx':
    manage_repo => true,
  }

  nginx::resource::server { $app_domain:
    listen_port              => $http_port,
    ssl                      => false,
    https_only               => false,
    http2                    => false,
    proxy                    => 'http://127.0.0.1:8080',
    proxy_set_header         => ['Host $host', 'X-Real-IP $remote_addr'],
    server_name              => [$app_domain],
    use_default_location     => true,
    redirect_http_to_https   => false,
  }
}
