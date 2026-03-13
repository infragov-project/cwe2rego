certificate { 'server_cert':
  ensure   => present,
  key_size => 1024,
  algorithm=> 'rsa',
}
