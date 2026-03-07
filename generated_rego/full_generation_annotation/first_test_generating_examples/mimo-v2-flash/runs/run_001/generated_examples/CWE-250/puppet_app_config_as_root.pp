file { '/etc/app/settings.conf':
  ensure  => file,
  content => 'api_key=your_secret_key',
  mode    => '0644',
  owner   => 'root',
  group   => 'root',
}
