class { 'profile::webserver':
  ssl_enabled   => false,
  listen_port   => 80,
  force_http    => true,
  redirect_https => false,
}
