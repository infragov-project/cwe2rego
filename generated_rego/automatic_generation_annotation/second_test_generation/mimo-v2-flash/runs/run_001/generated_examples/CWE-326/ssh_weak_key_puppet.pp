# A Puppet manifest to generate an SSH key with insufficient key length.
# This demonstrates CWE-326.

class ssh_weak_key {
  # CWE-326: Insufficient Key Lengths (RSA-1024)
  # This 'exec' resource explicitly generates an RSA key with a 1024-bit length.
  exec { 'generate_weak_ssh_host_key':
    command => 'ssh-keygen -t rsa -b 1024 -f /etc/ssh/ssh_host_rsa_key -N ""',
    path    => '/usr/bin:/bin:/usr/sbin:/sbin',
    creates => '/etc/ssh/ssh_host_rsa_key',
    before  => File['/etc/ssh/ssh_host_rsa_key.pub'], # Assume a public key is also managed
  }

  # Ensure permissions for the private key are correct after creation
  file { '/etc/ssh/ssh_host_rsa_key':
    ensure => file,
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
    require => Exec['generate_weak_ssh_host_key'],
  }

  file { '/etc/ssh/ssh_host_rsa_key.pub':
    ensure => file,
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
    require => Exec['generate_weak_ssh_host_key'],
  }
}

include ssh_weak_key
