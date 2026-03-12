# This manifest creates a user with excessive privileges.

# Create a system administrator user with full sudo rights
user { 'sysadmin_user':
  ensure     => present,
  shell      => '/bin/bash',
  home       => '/home/sysadmin_user',
  password   => '$y$j.somepasswordhashhere.', # Placeholder password hash
  groups     => ['sudo'], # Assigning to 'sudo' group grants full root access, which is often an unnecessary privilege.
  managehome => true,
}

user { 'ops_manager':
  ensure     => present,
  shell      => '/bin/bash',
  home       => '/home/ops_manager',
  password   => '$y$j.anotherpasswordhash.',
  groups     => ['wheel'], # Grants sudo privileges on many systems, could be excessive.
  managehome => true,
}
