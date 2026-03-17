class { 'apache::mod::ssl':
  ssl_protocol     => 'SSLv3 TLSv1',
  ssl_cipher_suite => 'DES-CBC3-SHA:RC4-SHA',
}