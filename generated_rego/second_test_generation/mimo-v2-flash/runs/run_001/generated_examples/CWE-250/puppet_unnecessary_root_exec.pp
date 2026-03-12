# puppet_unnecessary_root_exec.pp
# This command will execute as root by default if user is not specified.

exec { 'create_test_file':
  command  => '/bin/touch /var/log/app/app.log', # Runs as root by default - CWE-250
  creates  => '/var/log/app/app.log',
  path     => '/usr/local/bin:/usr/bin:/bin',
  # user     => 'appuser', # Leaving this out makes it run as root, an unnecessary privilege
  before   => File['/var/log/app'],
}

file { '/var/log/app':
  ensure => directory,
  owner  => 'appuser',
  group  => 'appuser',
  mode   => '0755',
}
