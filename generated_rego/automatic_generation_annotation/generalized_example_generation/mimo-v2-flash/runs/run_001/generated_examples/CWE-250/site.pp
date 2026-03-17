exec { 'update-system':
  command => '/usr/bin/apt-get update',
  user    => 'root',
  path    => ['/usr/bin', '/bin'],
}
