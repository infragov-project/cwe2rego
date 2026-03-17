file { '/var/www/html':
  ensure  => directory,
  owner   => 'root',
  group   => 'root',
  mode    => '0777',
  recurse => true,
}

file { '/etc/myapp/secrets.conf':
  ensure => file,
  owner  => 'root',
  group  => 'root',
  mode   => '0666',
  content => 'DB_PASSWORD=admin123',
}