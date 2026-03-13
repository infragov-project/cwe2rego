class apache::ssl {
  $ssl_protocol = 'SSLv3 +TLSv1'
  file { '/etc/httpd/conf.d/ssl.conf':
    ensure  => file,
    content => "SSLProtocol ${ssl_protocol}
",
  }
}
