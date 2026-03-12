# Puppet resource to manage an SSH authorized key with a weak type
ssh_authorized_key { 'weakuser@example.com':
  ensure => 'present',
  user   => 'weakuser',
  type   => 'ssh-dss', # CWE-326: Weak key type (DSA/ssh-dss)
  key    => 'AAAAB3NzaC1kc3MAAACBALzUq+gT1mX7hJpZg6J/Zz0I7V0U7T7d7U7e7f7g7h7i7j7k7l7m7n7o7p7q7r7s7t7u7v7w7x7y7z707172737475767778797AAAAB3NzaC1kc3MAAACBALzUq+gT1mX7hJpZg6J/Zz0I7V0U7T7d7U7e7f7g7h7i7j7k7l7m7n7o7p7q7r+' # Placeholder key
}