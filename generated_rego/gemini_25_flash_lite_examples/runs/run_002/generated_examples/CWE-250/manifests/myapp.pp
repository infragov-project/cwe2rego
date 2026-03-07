# manifests/myapp.pp

$app_user = 'puppet_user'
$app_home = "/home/${app_user}"
$app_data_dir = "${app_home}/data"

# Ensure the user exists
user { $app_user:
  ensure     => 'present',
  home       => $app_home,
  managehome => true,
  shell      => '/bin/bash',
}

# Ensure the data directory exists, owned by the app user
file { $app_data_dir:
  ensure => 'directory',
  owner  => $app_user,
  group  => $app_user,
  mode   => '0755',
}

# WEAKNESS: Using an exec resource to create a file as root.
# If $app_data_dir exists and is writable by $app_user, root is not needed.
exec { 'create_app_data_file':
  command => "touch ${app_data_dir}/initial.dat",
  user    => 'root', # CWE-250: Unnecessary privilege to create a file owned by a non-root user.
  group   => 'root', # CWE-250: Unnecessary privilege.
  creates => "${app_data_dir}/initial.dat",
  path    => ['/bin', '/usr/bin'],
  require => File[$app_data_dir],
}
