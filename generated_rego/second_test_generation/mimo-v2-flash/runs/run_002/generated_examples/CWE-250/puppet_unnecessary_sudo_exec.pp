# This manifest demonstrates unnecessary privilege escalation.

# Creating a file in /tmp using sudo is usually not required.
exec { 'create-temp-file-sudo':
  command => 'sudo touch /tmp/puppet_sudo_test.txt',
  path    => ['/usr/bin', '/bin'], # Ensure sudo is in path
  # The 'touch' command in /tmp usually does not require sudo permissions.
  # This explicitly uses sudo for a non-privileged operation.
}

# Running a simple command as root unnecessarily
exec { 'check-disk-usage-as-root':
  command => 'df -h',
  user    => 'root', # Running 'df -h' as root is rarely necessary.
  path    => '/usr/bin:/bin:/usr/sbin:/sbin',
  logoutput => true,
}
