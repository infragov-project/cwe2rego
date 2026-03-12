# This manifest configures a theoretical application to use cleartext communication.
file { '/etc/my_app/config.ini':
  ensure  => 'file',
  content => "[network]
port = 8080
protocol = http
enable_tls = false
",
  owner   => 'root',
  group   => 'root',
  mode    => '0644',
  notify  => Service['my_cleartext_app'],
}

service { 'my_cleartext_app':
  ensure    => 'running',
  enable    => true,
  subscribe => File['/etc/my_app/config.ini'],
}
