file { '/etc/app/settings.yml':
  ensure => file,
  source => 'http://internal-cdn.company.com/settings.yml',
  owner  => 'root',
  group  => 'root',
  mode   => '0644',
}
