# Example Puppet Manifest
# Scenario: An exec resource that runs a simple command, and privileges are unnecessarily elevated.

$command_to_run = "echo 'This is a test message.'"

exec { 'run_test_echo_root':
  command => $command_to_run,
  path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
  user    => 'root', # <-- CWE-250: 'root' user is unnecessary for 'echo'.
  unless  => "echo 'Already ran'",
}
