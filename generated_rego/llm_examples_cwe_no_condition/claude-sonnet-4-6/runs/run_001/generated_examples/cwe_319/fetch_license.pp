file { '/opt/myapp/license.key':
  ensure => present,
  source => 'http://licensing.example.com/private/keys/myapp.key',
  owner  => 'root',
  group  => 'root',
  mode   => '0600',
}

file { '/etc/myapp/credentials.conf':
  ensure  => present,
  source  => 'http://config.example.com/credentials/production.conf',
  owner   => 'myapp',
  group   => 'myapp',
  mode    => '0400',
  replace => true,
}
