file { '/etc/application/credentials.conf':
  ensure => file,
  source => 'http://legacy-config-server.example.com/app/v1/credentials.conf',
  owner  => 'appuser',
  group  => 'appgroup',
  mode   => '0600',
}
