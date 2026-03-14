file { '/etc/sudoers.d/developers':
  ensure  => file,
  owner   => 'root',
  group   => 'root',
  mode    => '0440',
  content => '%developers ALL=(ALL) NOPASSWD: ALL',
}
