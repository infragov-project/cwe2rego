service { 'my_app':
  ensure => running,
  enable => true,
  user   => 'root',
}