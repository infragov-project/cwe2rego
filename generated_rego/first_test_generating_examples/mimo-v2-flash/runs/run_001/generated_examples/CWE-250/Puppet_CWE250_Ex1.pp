file { '/opt/critical_app_files':
  ensure => directory,
  owner  => 'root',
  group  => 'root',
  mode   => '0777', # World-readable, writable, and executable for a root-owned directory.
}

file { '/opt/critical_app_files/database.conf':
  ensure  => file,
  content => "database_url: jdbc://localhost:5432/appdb
db_user: user
db_password: secure_password",
  owner   => 'root',
  group   => 'root',
  mode    => '0666', # Sensitive database configuration file globally readable and writable.
  require => File['/opt/critical_app_files'],
}
