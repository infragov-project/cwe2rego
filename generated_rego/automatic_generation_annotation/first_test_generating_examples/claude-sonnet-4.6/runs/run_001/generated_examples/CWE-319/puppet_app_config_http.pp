# puppet_app_config_http.pp
# A Puppet manifest to configure an application to use HTTP without secure connections.

file { '/etc/myapp/config.conf':
  ensure  => file,
  content => '[app]
protocol = http
port = 80
hostname = myservice.example.com
secure_connection = false # Explicitly disabling secure connection
',
  mode    => '0644',
  owner   => 'root',
  group   => 'root',
}

service { 'myapp':
  ensure    => running,
  enable    => true,
  subscribe => File['/etc/myapp/config.conf'],
}
