exec { 'system-cleanup':
  command => '/usr/bin/cleanup.sh',
  user    => 'root',
  path    => ['/usr/bin', '/bin'],
}
