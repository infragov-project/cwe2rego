apache::vhost { 'secure_site':
  ssl_protocol => ['SSLv3', 'TLSv1', 'TLSv1.1'],
  ssl_cipher_suite => 'DES-CBC3-SHA',
}