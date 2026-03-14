file { '/etc/sudoers.d/admin_user':
  ensure  => file,
  content => 'admin_user ALL=(ALL) NOPASSWD: ALL',
  mode    => '0440',
}