file { '/etc/database/conf.d/security.cnf':
  ensure  => file,
  content => "[security]
protocol = http
ssl_mode = DISABLED
require_secure_transport = OFF
",
  owner   => 'root',
  group   => 'root',
  mode    => '0644',
}