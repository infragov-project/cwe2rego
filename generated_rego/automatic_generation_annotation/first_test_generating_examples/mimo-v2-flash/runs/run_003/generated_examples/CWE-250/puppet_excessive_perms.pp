# puppet_excessive_perms.pp
# Manifest to create resources with overly permissive access

# WEAKNESS: Directory with world-writable permissions
file { '/opt/app/temp_upload_dir':
  ensure => directory,
  owner  => 'appuser',
  group  => 'appuser',
  mode   => '0777', # WEAKNESS: World-writable directory
}

# WEAKNESS: File with world-readable/writable permissions for sensitive data
file { '/etc/app/config/sensitive_db_creds.env':
  ensure  => file,
  owner   => 'appuser',
  group   => 'appuser',
  mode    => '0666', # WEAKNESS: World-readable/writable file
  content => 'DB_USERNAME=admin;DB_PASSWORD=secretpassword',
}

# WEAKNESS: An SSH authorized_keys file with world-writable permissions
# granting public write access to authorized keys for root.
file { '/root/.ssh/authorized_keys':
  ensure => file,
  owner  => 'root',
  group  => 'root',
  mode   => '0666', # WEAKNESS: World-writable authorized_keys file for root.
  content => 'ssh-rsa AAAAB3NzaC... insecure_key_for_anyone'
}
