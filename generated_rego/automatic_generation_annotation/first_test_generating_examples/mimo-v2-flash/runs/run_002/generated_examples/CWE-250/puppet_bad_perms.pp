# Define a critical configuration file
file { '/etc/webserver/config.ini':
  ensure  => 'file',
  content => "[general]
port = 8080
verbose = true
",
  owner   => 'root',
  group   => 'root',
  mode    => '0777', # CWE-250: Overly permissive file permissions for a configuration file
}
