openssl::certificate::generate { 'server_cert':
  key_size => 1024,
  digest   => 'md5',
}