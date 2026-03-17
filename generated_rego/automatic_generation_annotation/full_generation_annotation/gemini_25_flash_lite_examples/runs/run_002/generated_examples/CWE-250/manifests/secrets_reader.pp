# manifests/secrets_reader.pp

$app_user = 'puppet_user'
$app_home = "/home/${app_user}"
$app_secrets_file = "${app_home}/my_app/secrets.conf"

# Ensure user and secrets file preparation
user { $app_user:
  ensure     => 'present',
  home       => $app_home,
  managehome => true,
  shell      => '/bin/bash',
}

file { "${app_home}/my_app":
  ensure => 'directory',
  owner  => $app_user,
  group  => $app_user,
  mode   => '0750',
  require => User[$app_user],
}

file { $app_secrets_file:
  ensure  => 'present',
  owner   => $app_user,
  group   => $app_user,
  mode    => '0640',
  content => 'API_KEY=supersecret',
  require => File["${app_home}/my_app"],
}

# WEAKNESS: A script intended to read sensitive secrets, but executed as root.
# Ideally, it should run as the user owning the secrets or a dedicated service account.
exec { 'read_app_secrets_script':
  command => "/usr/local/bin/read_secrets.sh", # Assume this script exists
  user    => 'root', # CWE-250: Unnecessary privilege to read a user-owned sensitive file.
  group   => 'root', # CWE-250: Unnecessary privilege.
  path    => ['/bin', '/usr/bin'],
  onlyif  => 'test -f /opt/myapp/monitor_service', # Example guard
  subscribe => File[$app_secrets_file],
}
