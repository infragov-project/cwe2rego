class { 'apache::mod::ssl':
  ssl_protocol   => ['SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2'],
  ssl_cipher     => 'DEFAULT:!DH',
  ssl_options    => ['StdEnvVars'],
}