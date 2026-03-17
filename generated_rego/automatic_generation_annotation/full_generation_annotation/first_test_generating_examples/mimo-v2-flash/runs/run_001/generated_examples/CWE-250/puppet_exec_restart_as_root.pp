exec { 'restart-service':
  command => '/usr/bin/systemctl restart myapp.service',
  path    => '/usr/bin:/bin:/usr/sbin:/sbin',
  refreshonly => true,
}
