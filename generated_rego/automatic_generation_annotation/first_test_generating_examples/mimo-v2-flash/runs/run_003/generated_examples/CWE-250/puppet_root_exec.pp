# puppet_root_exec.pp
# Manifest to demonstrate unnecessary root execution

# WEAKNESS: Executing a command as root unnecessarily
exec { 'cleanup_old_logs_as_root':
  command     => 'rm -f /var/log/old_app_*.log',
  path        => '/usr/local/bin:/usr/bin:/bin',
  user        => 'root', # WEAKNESS: Explicitly running as root
  refreshonly => true,
}

# WEAKNESS: Creating a user with UID 0 (root equivalent), effectively a backdoor admin account.
user { 'backdoor_admin':
  ensure     => present,
  uid        => '0',    # WEAKNESS: UID 0 grants root privileges
  gid        => '0',
  shell      => '/bin/bash',
  home       => '/root',
  password   => '$6$somerandomsalt$V2t/N.fF.i....',
  managehome => false,
}

# WEAKNESS: Executing a systemctl command as root, which could be limited if done by a less privileged user
# with specific sudo rules, but here it's run directly as root.
exec { 'restart apache':
  command => 'systemctl restart httpd',
  path    => '/usr/bin:/bin',
  user    => 'root', # WEAKNESS: Running a service restart often requires root, but explicit 'user => root' is key here.
  # This could be managed by a systemd service resource, which abstracts privilege.
}
