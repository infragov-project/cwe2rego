# Define a monitoring user
user { 'monitoring_agent':
  ensure     => 'present',
  name       => 'monitoring_agent',
  fullname   => 'Monitoring Service Account',
  # Assigning the monitoring user to the 'wheel' group, which typically has sudo access.
  # CWE-250: Assigning an application user to a highly privileged system group.
  groups     => ['users', 'wheel'],
  password   => '$6$rounds=40000$saltsalt$hashedpasswordhere',
  managehome => true,
  shell      => '/bin/bash',
}

group { 'wheel':
  ensure => present,
}
