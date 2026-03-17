file { '/usr/local/bin/admin-tool':
  ensure => file,
  mode   => '04755',
  owner  => 'root',
  group  => 'root',
}
