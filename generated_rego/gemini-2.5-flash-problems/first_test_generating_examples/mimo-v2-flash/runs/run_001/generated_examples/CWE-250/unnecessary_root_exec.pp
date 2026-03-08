# file: unnecessary_root_exec.pp
# This manifest executes a command that doesn't strictly need root,
# but the 'exec' resource runs as root by default unless 'user' is specified.

file { '/var/log/my_app_status.log':
  ensure  => file,
  owner   => 'app_user',
  group   => 'app_group',
  mode    => '0640',
  content => 'Application status initialized.',
}

exec { 'append_app_status':
  command => "echo 'Service started successfully at `date`.' >> /var/log/my_app_status.log",
  # By default, this exec will run as 'root'.
  # If 'app_user' has write permissions to the file, and is a less privileged user,
  # this command could be run as 'user => "app_user"'.
  # Running it implicitly as root is a CWE-250 as it's an unnecessary privilege.
  path    => ['/usr/bin', '/bin'],
  require => File['/var/log/my_app_status.log'],
}