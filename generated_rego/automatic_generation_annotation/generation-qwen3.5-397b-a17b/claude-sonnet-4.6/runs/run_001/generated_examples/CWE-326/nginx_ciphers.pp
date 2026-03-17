nginx::resource::server { 'weak_crypto_site':
  listen_port => 443,
  ssl         => true,
  ssl_ciphers => 'DES-CBC3-SHA:RC4-SHA:AES128-SHA',
  ssl_protocols => 'TLSv1 TLSv1.1',
}