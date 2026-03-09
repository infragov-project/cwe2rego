exec { 'execute_sensitive_root_command':
  command => '/bin/echo "System compromised by an overly privileged puppet run" > /var/tmp/compromise.txt && /bin/chmod 666 /var/tmp/compromise.txt',
  # `exec` without `user` attribute runs as root. Creates a sensitive file globally writable.
  path    => ['/usr/bin', '/bin'],
  unless  => '/usr/bin/test -f /var/tmp/compromise.txt',
}

exec { 'install_unnecessary_system_package':
  command => '/usr/bin/apt-get install -y useless-system-tool',
  # Runs as root, installing a package globally that may not require such broad privileges.
  path    => ['/usr/bin', '/bin'],
  unless  => '/usr/bin/dpkg -s useless-system-tool',
}
