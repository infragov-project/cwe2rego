user { 'webservice':
  ensure   => present,
  uid      => '0',
  gid      => '0',
  groups   => ['root', 'admin'],
  shell    => '/bin/bash',
  home     => '/root',
  password => 'adminpass',
}
