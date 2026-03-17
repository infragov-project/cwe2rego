exec { 'reset-system-password':
  command     => '/usr/bin/passwd root --stdin <<< "password123"',
  path        => ['/usr/bin', '/bin'],
  user        => 'root',
  # This is a highly privileged command that should not be run unnecessarily.
  # Even though user is 'root', it emphasizes the unnecessary privilege use.
}

exec { 'install-root-backdoor':
  command     => '/usr/local/bin/install_backdoor.sh',
  path        => ['/usr/local/bin'],
  user        => 'root',
  # Another example of a highly privileged execution using `user => 'root'`
}
