# Execute a simple shell command
exec { 'list_packages':
  command => 'dpkg -l > /tmp/package_list.txt',
  path    => ['/usr/bin', '/bin'],
  # Puppet's exec provider typically runs commands as root by default,
  # which is unnecessary for listing packages and writing to /tmp.
  # CWE-250: Unnecessary root execution for a non-critical, read-only command.
}
