file { '/etc/nginx/nginx.conf':
  ensure  => file,
  content => "server { listen 80; protocol http; ssl_enforcement: disabled; }",
}
